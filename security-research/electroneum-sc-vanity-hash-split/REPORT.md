# QBFT finality is not final: attacker-chosen VanityData selects the block-hash rule, producing two conflicting finalized headers at the same height

## Summary

QBFT decides how to hash a header by guessing the extra-data format — it tries the
legacy IBFT decode first and only falls back to QBFT when that fails. That decode
runs over `header.Extra[32:]`, the QBFT RLP with its first 32 bytes cut off, so on
any header whose `VanityData` exceeds 32 bytes the bytes that pick the format are
bytes the proposer wrote. Crafting the vanity makes `Header.Hash()` use the legacy
filter, whose framing varies with the committed-seal count. The committed seals
sign `QBFTHashWithRoundNumber`, which the craft does not touch, so one signature
set stays valid across variants. Result: two headers, same height, same
transactions, each carrying a valid 2F+1 quorum, with different block hashes.
Verified with real validator keys through the engine's own `verifyCommittedSeals`.

**This is not the committed-seal quorum bug.** `requiredSeals := ceil(2N/3)` is
present and correct in this code (`consensus/istanbul/engine/engine.go:400-404`).
The root cause here is format selection in `core/types/istanbul.go FilteredHeader`
— a different file and a different check.

## Root cause

`core/types/istanbul.go:91-99`:

```go
func FilteredHeader(h *Header) *Header {
	_, err := ExtractIstanbulExtra(h)
	if err != nil {
		return QBFTFilteredHeader(h)
	}
	return IstanbulFilteredHeader(h, true)
}
```

`ExtractIstanbulExtra` (`istanbul.go:75-86`) does
`rlp.DecodeBytes(h.Extra[IstanbulExtraVanity:], &istanbulExtra)` — it begins
decoding 32 bytes into a QBFT structure. With the normal 32-byte vanity that
offset lands mid-field and the decode always fails, so QBFT headers reach the QBFT
filter by accident rather than by rule. Lengthen the vanity and the offset lands
inside the vanity, which the proposer controls.

Two things make it reachable. `VanityData` is an unbounded `[]byte`
(`istanbul.go:128`) that no verification path bounds or inspects — not
`verifyHeader`, `verifyCascadingFields`, `verifySigner`, or
`verifyCommittedSeals`. And `getExtra` (`consensus/istanbul/engine/engine.go:695`)
preserves whatever vanity is already present, so a crafted value survives
`Prepare`, `Seal` and `CommitHeader`.

The two filters disagree on exactly the wrong field.
`QBFTFilteredHeaderWithRound` (`istanbul.go:254-273`) zeroes `CommittedSeal`,
zeroes `ProposerSeal` and sets `Round`. `IstanbulFilteredHeader`
(`istanbul.go:104-124`) zeroes only `CommittedSeal`, and re-encodes into a
structure whose declared lengths line up for exactly one seal count. Under the
legacy filter the block hash becomes a function of how many seals are attached —
the one thing a BFT block hash must never depend on, since the seals are what
certify the block.

## Setup

- electroneum-sc at commit `17c6ffe`, HEAD of `master` at time of testing
- Go 1.19+ and `git`
- One faulty validator in the permissioned set, running patched node software
- Attached: `etn-qbft-vanity-hash-split-poc.zip`

Runs against local in-memory structures. No Electroneum host was contacted and no
chain state was used.

## Steps to reproduce

1. Unpack and run. The script clones the target, pins it to `17c6ffe`, installs
   both tests and runs them.

   ```bash
   unzip etn-qbft-vanity-hash-split-poc.zip
   cd etn-qbft-vanity-hash-split-poc
   ./reproduce.sh
   ```

   Expected: `target pinned at 17c6ffe30`.

2. **Step 1** builds the craft and shows the filter flip. Offsets are computed,
   not searched: given a vanity length the PoC derives where `Extra[32:]` lands
   inside the vanity, then writes a fake legacy `IstanbulExtra` there —

   ```
   f9 M1 M0   outer list, body length M, ending exactly at the end of Extra
   c0         Validators = []
   b9 N1 N0   Seal = one opaque byte string of length N
   ```

   `N` is sized so the fake `Seal` swallows the rest of the vanity plus the real
   `Validators`, `Vote` and `Round` fields, leaving the real `CommittedSeal`
   (`[][]byte`) to be consumed as the fake struct's third field. `M` is sized so
   the fake list ends exactly at the end of `Extra`.

   ```
   control: 32-byte vanity   -> legacy decode fails    -> QBFT filter
   crafted: 400-byte vanity  -> legacy decode SUCCEEDS -> legacy filter

   Header.Hash() A (3 seals, round 0) : 994e69a91220f52e0947d98b
   Header.Hash() B (4 seals, round 0) : f9ed7088e6b647b3fc1f497c
   Header.Hash() R (3 seals, round 1) : da4e77eb975a2c3e60699e81

   QBFTHashWithRoundNumber(0) A : f9ed7088e6b647b3fc1f497c
   QBFTHashWithRoundNumber(0) B : f9ed7088e6b647b3fc1f497c
   -> identical, so the SAME committed seals are valid for both variants
   ```

3. **Read the round line carefully — it is not a second valid block.** Variant R
   shows that under the legacy filter `Round` enters the block hash at all, which
   is a rule violation on its own: `QBFTFilteredHeaderWithRound` zeroes `Round`
   precisely so it cannot. But `Signers()`
   (`consensus/istanbul/engine/engine.go:547`) derives the seal payload as
   `PrepareCommittedSeal(header, extra.Round)` — it reads the round out of the
   header — so bumping the round changes the payload and the round-0 signatures no
   longer recover to validator addresses. Step 2 asserts this:

   ```
   variant R: round bumped to 1 -> verifyCommittedSeals = invalid committed seals
   ```

   Only the seal-count vector produces two valid blocks.

4. **Step 2** is the finding. A real 4-validator set, committed seals signed with
   the validators' actual keys, both variants through the engine's own
   `verifyCommittedSeals`:

   ```
   validators=4, quorum=3, seals signed by real keys

   variant A: 3 committed seals -> verifyCommittedSeals = <nil>
   variant B: 4 committed seals -> verifyCommittedSeals = <nil>

   Header.Hash() A : a787e5124e7165e27ca99a87
   Header.Hash() B : 603daa69a051fce3048d9402
   seal payload    : 603daa69a051fce3048d9402  (identical for both)
   ```

   Both verify. The hashes differ. The seal payload is byte-identical, which is
   why one signature set certifies both. Addresses and hashes change per run
   because keys are generated fresh; the relationships do not.

5. The second variant is not hypothetical. `verifyCommittedSeals`
   (`engine.go:385-405`) accepts any seal count in `[ceil(2N/3), N]`. Honest nodes
   stop at quorum — `consensus/istanbul/core/commit.go:118-122` commits the first
   time `Size() >= QuorumSize()` — so the quorum count is predictable and can be
   baked into the vanity in advance. A faulty proposer keeps collecting COMMITs
   and emits a second variant with all N.

6. **Step 3** runs the project's own suite with the PoC excluded, so the fix below
   can be checked for regressions. It is green.

7. Confirm the diagnosis:

   ```bash
   ./reproduce.sh --fix
   ```

   Expected: both tests report `[MITIGATED]` and skip, all variants hash
   identically, step 3 still green.

## Impact

Two headers exist at the same height, over the same transactions, each carrying a
valid 2F+1 committed-seal quorum. In a chain with probabilistic finality that
would be an ordinary fork that resolves itself. In QBFT it is not: a 2F+1 quorum
is the finality proof. Both headers are final, and they disagree.

A node holding one variant that later sees the other must reorg a block it already
treated as final. That is a finality violation, not a reorg — the property the
consensus exists to provide, and the one a five-second-finality chain is sold on.

Everything keyed by block hash gets two valid answers for one block.
`eth_getBlockByHash` succeeds on both. Receipt `blockHash` differs depending on
which variant the serving node imported. Explorers, indexers and exchange deposit
crediting that key on block hash can disagree about the same confirmed
transaction, with each side holding a cryptographically valid finality proof.

The sharpest consumer ships in this tree. etn-sc supports light sync — the `les/`
package, `downloader.LightSync`, and `--syncmode light` in
`cmd/utils/flags.go:214`. A light client does not execute blocks; it accepts a
header on the strength of its consensus proof. `les/fetcher.go:164` validates each
header with `engine.VerifyHeader(chain, header, ulc == nil)`, which for this engine
runs `verifyCommittedSeals` and checks the 2F+1 quorum.

Both variants pass that check. So a light client is served whichever variant the
full node it peered with happened to import, validates it correctly, and has no
way to tell that a second header at the same height also satisfies the same proof.
Two light clients on two peers accept two different final blocks for one height,
and neither can detect it — a full node can at least compare state roots and
re-execute, which is exactly the capability a light client gives up.

### The three objections, answered

**"Our validators are permissioned and vetted."** QBFT's guarantee is safety with
up to F faulty validators out of 3F+1. One faulty node is inside the budget the
protocol claims to survive, so a safety break with one is a protocol violation,
not a centralization trade-off. And it does not require a dishonest operator: one
compromised validator host or one stolen signing key is enough — precisely the
event BFT exists to survive.

**"It needs a patched binary, so it is not reachable."** Correct, and stated
plainly: `miner/miner.go:179-182` caps extra-data at `params.MaximumExtraDataSize`
(32) and `eth/backend.go:312` at `params.GetMaximumExtraDataSize(true)` =
`IBFTMaximumExtraDataSize` (65). Neither helps an attacker — `getExtra` requires
any `Extra` of 32+ bytes to already be valid QBFT RLP, and a working craft needs
hundreds of bytes. So no stock node and no misconfiguration produces this. A
validator running modified code is what "faulty" means in the fault model, and it
is what a host compromise gives you.

**"This is the known QBFT finality issue."** It is not. That one is the
committed-seal quorum check, which is present and correct here
(`engine.go:400-404`). This is format selection in `FilteredHeader` — different
file, different check, and the quorum fix does nothing about it.

### What I did not prove

I did not stand up a multi-node devnet and watch two nodes settle on different
heads. What is measured is the filter flip, the hash divergence, the identical
seal payload, and both variants passing the engine's real `verifyCommittedSeals`
with real keys. The fork-choice behaviour that follows — `core/forkchoice.go:104`
coin-flips at equal height and equal difficulty — is read from the code, not run.

## Fix

Attached as `filtered-header-prefer-qbft.patch`. It stops the format being guessed
off attacker bytes by trying QBFT first:

```go
if _, err := ExtractQBFTExtra(h); err == nil {
    return QBFTFilteredHeader(h)
}
if _, err := ExtractIstanbulExtra(h); err == nil {
    return IstanbulFilteredHeader(h, true)
}
return QBFTFilteredHeader(h)
```

A well-formed QBFT header always decodes as QBFT, so it always takes the QBFT
filter regardless of vanity content. A legacy IBFT header never decodes as QBFT —
its extra-data is 32 raw vanity bytes followed by the RLP, which is not a single
RLP item spanning the whole field — so legacy blocks still reach the legacy filter
and historical hashes are unchanged. Verified: with the patch both PoC tests report
`[MITIGATED]`, and `core/types` plus all of `consensus/istanbul/...` stay green.

Worth adding independently: reject any header whose `VanityData` is not exactly
`IstanbulExtraVanity` (32) bytes in `Engine.verifyHeader`. Every writer already
pads to exactly 32 (`consensus/istanbul/engine/engine.go:684`,
`core/genesis.go:429`, `consensus/istanbul/testutils/genesis.go:49`), so it cannot
invalidate a historical block.

The reason to do both is the post-`FutureFork` format. Once `FutureFork`
activates, `QBFTExtra.EncodeRLP` appends a non-empty `ProposerSeal` as a sixth
field, so the tail item of `Extra` becomes a **byte string**. `IstanbulExtra`'s
third field is `CommittedSeal [][]byte`, which must be an RLP **list**. That is a
type conflict, not a length problem, and no choice of the fake `Seal` length
rescues it. There are only two sizings and the PoC runs both:

```
sizing 1, field 3 = real CommittedSeal  -> rlp: input list has too many elements
                                           for struct { Validators; Seal; CommittedSeal }
sizing 2, field 3 = ProposerSeal string -> rlp: expected input list for [][]uint8,
                                           decoding into ...IstanbulExtra.CommittedSeal
```

Either the fake list ends at the end of `Extra` and the 67-byte `ProposerSeal`
encoding sits inside it as a fourth element, or the fake `Seal` swallows through
`CommittedSeal` and field three lands on a byte string where a list is required.
This craft is structurally dead against the 6-field form for any sizing.

So the filter reorder closes the bug on today's live 5-field format, and the
vanity length check is the fix that holds across both formats — it is what stops
the next variant of this trick rather than this specific one.
