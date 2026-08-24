# QBFT block hash is chosen by attacker-controlled VanityData — one block, two valid hashes

## Summary

QBFT decides how to hash a header by guessing the extra-data format: it tries the
legacy IBFT decode first and only falls back to QBFT when that fails. The legacy
decode runs over `header.Extra[32:]` — the QBFT RLP with its first 32 bytes cut
off — so on any header whose `VanityData` is longer than 32 bytes, the bytes that
decide the format are bytes the proposer chose. Crafting the vanity makes
`Header.Hash()` use the legacy filter, which keeps `Round` and whose framing
varies with the committed-seal count. Neither belongs in a QBFT block hash. The
committed seals sign `QBFTHashWithRoundNumber`, which the craft does not touch, so
one signature set stays valid across variants. With real validator keys, two
variants of the same block both pass `verifyCommittedSeals` and hash differently.

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
`rlp.DecodeBytes(h.Extra[IstanbulExtraVanity:], &istanbulExtra)`. It starts
decoding 32 bytes into a QBFT structure. With the normal 32-byte vanity that
offset lands mid-field and the decode always fails, so QBFT headers get the QBFT
filter by accident rather than by rule. Make the vanity longer and the offset
lands inside the vanity itself, which the proposer writes.

Two things make that reachable. `VanityData` is an unbounded `[]byte`
(`istanbul.go:128`) that no verification path bounds or inspects — not
`verifyHeader`, not `verifyCascadingFields`, not `verifySigner`, not
`verifyCommittedSeals`. And `getExtra` (`consensus/istanbul/engine/engine.go:695`)
preserves whatever vanity is already there, so a crafted value survives `Prepare`,
`Seal` and `CommitHeader` untouched.

The two filters disagree on exactly the wrong fields.
`QBFTFilteredHeaderWithRound` (`istanbul.go:254-273`) zeroes `CommittedSeal`,
zeroes `ProposerSeal` and sets `Round`. `IstanbulFilteredHeader`
(`istanbul.go:104-124`) zeroes only `CommittedSeal`, and it re-encodes into a
structure whose declared lengths only line up for one specific seal count. So
under the legacy filter the block hash becomes a function of `Round` and of how
many seals are attached.

## Setup

- electroneum-sc at commit `17c6ffe`, HEAD of `master` at time of testing
- Go 1.19+ and `git`
- One Byzantine validator in the permissioned set, running patched node software
  (see the limits at the end of Impact)
- Attached: `etn-qbft-vanity-hash-split-poc.zip`

Everything runs against local in-memory structures. No Electroneum host was
contacted and no chain state was used.

## Steps to reproduce

1. Unpack and run. The script clones the target, pins it to `17c6ffe`, installs
   the two tests and runs them.

   ```bash
   unzip etn-qbft-vanity-hash-split-poc.zip
   cd etn-qbft-vanity-hash-split-poc
   ./reproduce.sh
   ```

   Expected: `target pinned at 17c6ffe30`.

2. **Step 1 of the run** builds the craft and shows the filter flip. The offsets
   are computed, not searched: given a vanity length the PoC derives where
   `Extra[32:]` lands inside the vanity, then writes a fake legacy `IstanbulExtra`
   there —

   ```
   f9 M1 M0   outer list, body length M, ending exactly at the end of Extra
   c0         Validators = []
   b9 N1 N0   Seal = one opaque byte string of length N
   ```

   `N` is sized so the fake `Seal` swallows the rest of the vanity plus the real
   `Validators`, `Vote` and `Round` fields, which leaves the real `CommittedSeal`
   (`[][]byte`) to be consumed as the fake struct's third field. `M` is sized so
   the fake list ends exactly at the end of `Extra`, leaving no trailing bytes.

   Expected output:

   ```
   control: 32-byte vanity   -> legacy decode fails    -> QBFT filter
   crafted: 400-byte vanity  -> legacy decode SUCCEEDS -> legacy filter

   variant A (3 seals, round 0): legacy decode err=<nil>                            -> LEGACY filter
   variant B (4 seals, round 0): legacy decode err=rlp: element is larger than list -> QBFT filter
   variant R (3 seals, round 1): legacy decode err=<nil>                            -> LEGACY filter

   Header.Hash() A : 994e69a91220f52e0947d98b
   Header.Hash() B : f9ed7088e6b647b3fc1f497c
   Header.Hash() R : da4e77eb975a2c3e60699e81

   QBFTHashWithRoundNumber(0) A : f9ed7088e6b647b3fc1f497c
   QBFTHashWithRoundNumber(0) B : f9ed7088e6b647b3fc1f497c
   -> identical, so the SAME committed seals are valid for both variants

   SPLIT: seal count changes Header.Hash() (994e69a91220f52e vs f9ed7088e6b647b3) while the seal payload is identical
   SPLIT: round changes Header.Hash() (994e69a91220f52e vs da4e77eb975a2c3e) for the same prepared block
   --- FAIL: TestVanityData_FlipsHashFilter
   ```

   The test asserts that all three hash the same, which is what the QBFT rule
   requires. The failure is the finding.

3. **Step 2 of the run** is the one that matters. It builds a real 4-validator
   set, signs committed seals with the validators' actual keys over
   `PrepareCommittedSeal`, and runs both variants through the engine's own
   `verifyCommittedSeals`:

   ```
   validators=4, quorum=3, seals signed by real keys

   variant A: 3 committed seals -> verifyCommittedSeals = <nil>
   variant B: 4 committed seals -> verifyCommittedSeals = <nil>

   Header.Hash() A : 70fb6dccc8a6cd5b89389873
   Header.Hash() B : bc5c65caac5fc488fb31c187
   seal payload    : bc5c65caac5fc488fb31c187  (identical for both)

   CONSENSUS SPLIT: one block, two valid hashes.
   --- FAIL: TestVanitySplit_BothVariantsVerify
   ```

   Both verify. The hashes differ. The seal payload is byte-identical, which is
   why one signature set authenticates both. Addresses and hashes change per run
   because the validator keys are generated fresh; the relationships do not.

4. The second variant is not hypothetical. `verifyCommittedSeals`
   (`consensus/istanbul/engine/engine.go:385-405`) accepts any seal count in
   `[ceil(2N/3), N]`. Honest nodes stop at quorum —
   `consensus/istanbul/core/commit.go:118-122` commits the first time
   `Size() >= QuorumSize()` — so the quorum count is predictable and can be baked
   into the vanity in advance. A Byzantine proposer keeps collecting COMMITs and
   emits a second variant with all N.

5. **Step 3 of the run** runs the project's own suite with the PoC excluded, so
   the fix below can be checked for regressions. It is green.

6. Confirm the diagnosis:

   ```bash
   ./reproduce.sh --fix
   ```

   Expected: both tests report `[MITIGATED]` and skip, every variant hashes
   identically, and step 3 is still green. One line of step 1 still reads
   `legacy decode SUCCEEDS` — that is correct. The fix does not stop the legacy
   decode from parsing, it stops `FilteredHeader` from acting on it.

## Impact

One Byzantine validator, during its own round-robin proposer turn, finalizes a
block that exists under two distinct hashes, both carrying a valid 2F+1
committed-seal quorum. Honest nodes that receive different variants record
different canonical heads at the same height. Both variants are height N with
`Difficulty == istanbulcommon.DefaultDifficulty`, so `externTd == localTd` and
`header.Number == current.Number`, which lands on `core/forkchoice.go:104`:

```go
reorg = !currentPreserve && (externPreserve || f.rand.Float64() < 0.5)
```

Each node independently coin-flips which of the two valid blocks it keeps. No
quorum of malicious nodes, no partition and no timing race are needed. One faulty
node out of 3F+1 is inside QBFT's declared fault budget, which is what makes a
safety break here a protocol violation rather than expected behaviour.

Three limits, stated plainly.

It needs a **patched binary**. `miner/miner.go:179-182` rejects extra-data over
`params.MaximumExtraDataSize` (32) and `eth/backend.go:312` caps it as well, so no
stock node and no misconfiguration produces a 400-byte vanity. The attacker runs
modified code — which is what "Byzantine" means in this fault model, but it does
rule this out as an accident.

It is **not reachable by an unauthenticated peer**. Either variant needs 2F+1
valid committed seals, which a non-validator cannot forge.

I **did not observe a live fork**. What is measured is the filter flip, the hash
divergence, the identical seal payload, and both variants passing the engine's
real `verifyCommittedSeals` with real keys. The fork-choice consequence above is
read from `core/forkchoice.go:90-106`, not run. Closing that gap needs a devnet
with a patched proposer, which I did not build.

## Fix

Attached as `filtered-header-prefer-qbft.patch`. It stops the format from being
guessed off attacker bytes by trying QBFT first:

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
filter no matter what the vanity contains. A legacy IBFT header never decodes as
QBFT — its extra-data is 32 raw vanity bytes followed by the RLP, which is not a
single RLP item spanning the whole field — so legacy blocks still reach the legacy
filter and historical hashes are unchanged. Verified: with the patch applied both
PoC tests report `[MITIGATED]`, and `core/types` plus all of
`consensus/istanbul/...` stay green.

Worth doing as well, independently: reject any header whose `VanityData` is not
exactly `IstanbulExtraVanity` (32) bytes in `Engine.verifyHeader`. Every writer
already pads to exactly 32 (`consensus/istanbul/engine/engine.go:684`,
`core/genesis.go:429`, `consensus/istanbul/testutils/genesis.go:49`), so it cannot
invalidate a historical block, and it removes the unbounded-vanity growth surface
at the same time. The filter fix is the one that closes this bug; the length check
is what stops the next variant of the same trick.
