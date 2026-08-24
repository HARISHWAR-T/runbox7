# Attacker-chosen VanityData selects which hashing rule Header.Hash() uses, so one Byzantine validator can finalize the same block under two valid hashes

## Summary

QBFT decides how to hash a header by *guessing* the extra-data format: it tries
the legacy IBFT decode first and falls back to QBFT if that fails. The legacy
decode is run over `header.Extra[32:]` — the QBFT RLP with its first 32 bytes cut
off — so any header whose `VanityData` is longer than 32 bytes puts the
discriminator inside attacker-chosen bytes. A proposer that crafts its vanity
makes `Header.Hash()` use the legacy filter, which does **not** zero `Round` and
whose framing depends on the committed-seal count — the two fields QBFT must
exclude from the block hash. The committed seals sign `QBFTHashWithRoundNumber`,
which is unaffected, so one signature set stays valid across variants. With real
validator keys, two variants of the same block both pass `verifyCommittedSeals`
and hash differently.

## Setup

- electroneum-sc at commit `17c6ffe` (HEAD of `master` at time of testing)
- Go 1.19+
- One Byzantine validator inside the permissioned set, **running patched node
  software**. See "Attacker capability" below — this is not reachable with a
  stock binary and not reachable by an external peer.

Runs entirely against local in-memory structures. No Electroneum host contacted.

## Steps to reproduce

```bash
git clone https://github.com/electroneum/electroneum-sc.git && cd electroneum-sc
git checkout 17c6ffe
cp <this>/poc/zz_vanity_split_test.go        core/types/
cp <this>/poc/zz_vanity_split_engine_test.go consensus/istanbul/engine/

go test ./core/types/                 -run TestVanityData_FlipsHashFilter   -v
go test ./consensus/istanbul/engine/  -run TestVanitySplit_BothVariantsVerify -v
```

1. **The discriminator is attacker-controlled.** `core/types/istanbul.go:91-99`:

   ```go
   func FilteredHeader(h *Header) *Header {
       _, err := ExtractIstanbulExtra(h)
       if err != nil {
           return QBFTFilteredHeader(h)
       }
       return IstanbulFilteredHeader(h, true)
   }
   ```

   and `ExtractIstanbulExtra` (`istanbul.go:75-86`) does
   `rlp.DecodeBytes(h.Extra[IstanbulExtraVanity:], &istanbulExtra)` — it decodes
   starting 32 bytes into a QBFT structure. With a 32-byte vanity that offset
   lands mid-field and the decode always fails. With a longer vanity it lands
   inside the vanity itself.

   `VanityData` is an unbounded `[]byte` (`istanbul.go:128`) and is preserved
   verbatim through `getExtra` (`consensus/istanbul/engine/engine.go:695`), so it
   survives `Prepare`, `Seal` and `CommitHeader` untouched. Nothing in
   `verifyHeader`, `verifyCascadingFields`, `verifySigner` or
   `verifyCommittedSeals` ever inspects it.

2. **The craft.** The PoC computes, not guesses, the offsets. At `Extra[32:]` it
   writes a fake legacy `IstanbulExtra`:

   ```
   f9 M1 M0   outer list, body length M, ending exactly at the end of Extra
   c0         Validators = []
   b9 N1 N0   Seal = one opaque byte string of length N
   ```

   `N` is sized so the fake `Seal` swallows the rest of the vanity plus the real
   `Validators`, `Vote` and `Round` fields, leaving the real `CommittedSeal`
   (`[][]byte`) to be consumed as the fake struct's third field. `M` is sized so
   the fake list ends exactly at the end of `Extra`, leaving no trailing bytes.

3. **First test output** — the filter flips, and the hash starts depending on
   the wrong things:

   ```
   control: 32-byte vanity   -> legacy decode fails    -> QBFT filter
   crafted: 400-byte vanity  -> legacy decode SUCCEEDS -> legacy filter

   variant A (3 seals, round 0): legacy decode err=<nil>                              -> LEGACY filter
   variant B (4 seals, round 0): legacy decode err=rlp: element is larger than list   -> QBFT filter
   variant R (3 seals, round 1): legacy decode err=<nil>                              -> LEGACY filter

   Header.Hash() A : 994e69a91220f52e0947d98b
   Header.Hash() B : f9ed7088e6b647b3fc1f497c
   Header.Hash() R : da4e77eb975a2c3e60699e81

   QBFTHashWithRoundNumber(0) A : f9ed7088e6b647b3fc1f497c
   QBFTHashWithRoundNumber(0) B : f9ed7088e6b647b3fc1f497c
   -> identical, so the SAME committed seals are valid for both variants
   ```

4. **Second test — the one that matters.** A real 4-validator set, committed
   seals signed with the validators' actual keys, run through the engine's own
   `verifyCommittedSeals`:

   ```
   validators=4, quorum=3, seals signed by real keys

   variant A: 3 committed seals -> verifyCommittedSeals = <nil>
   variant B: 4 committed seals -> verifyCommittedSeals = <nil>

   Header.Hash() A : 72c1e6a8485675d0d5a87ae4
   Header.Hash() B : 1b648e3b24d90fd139aa2f6d
   seal payload    : 1b648e3b24d90fd139aa2f6d  (identical for both)
   ```

   Both verify. The hashes differ. The seal payload is byte-identical, which is
   why one signature set authenticates both.

   The degree of freedom is real: `verifyCommittedSeals`
   (`consensus/istanbul/engine/engine.go:385-405`) accepts any seal count in
   `[ceil(2N/3), N]`, so a Byzantine proposer that keeps collecting COMMITs can
   emit a second variant with more seals than the quorum honest nodes stop at.

## Attacker capability

One Byzantine validator, during its normal round-robin proposer turn. No quorum
of malicious nodes, no partition, no timing race. That is inside QBFT's declared
fault budget of F out of 3F+1, which is what makes a safety break here a protocol
violation rather than expected behaviour.

It is **not** reachable by an unauthenticated peer: producing either variant needs
2F+1 valid committed seals, which a non-validator cannot forge.

It is **not** reachable with a stock binary. `miner/miner.go:179-182` rejects
extra-data over `params.MaximumExtraDataSize` (32) and `eth/backend.go:312` caps
it too, so an honest node cannot be configured into emitting a 400-byte vanity.
The attacker must run modified node code — which is precisely what "Byzantine"
means in the fault model, but it does mean this is not a misconfiguration risk.

## Impact

The same finalized block exists under two distinct hashes, both carrying a valid
2F+1 committed-seal quorum. Honest nodes that receive different variants record
different canonical heads at the same height. Both variants are height N with
`Difficulty == istanbulcommon.DefaultDifficulty`, so `externTd == localTd` and
`header.Number == current.Number`, landing on `core/forkchoice.go:104`:

```go
reorg = !currentPreserve && (externPreserve || f.rand.Float64() < 0.5)
```

Each node independently coin-flips which of the two valid blocks it keeps.

What is measured: the filter flip, the hash divergence, the identical seal
payload, and both variants passing the engine's real `verifyCommittedSeals` with
real keys. What is **not** measured: I did not stand up a multi-node devnet and
observe two nodes actually settling on different heads. The fork-choice
consequence above is read from `core/forkchoice.go:90-106`, not observed running.
Closing that gap needs a devnet with a patched proposer, which I did not build.

## Root cause

`core/types/istanbul.go:91-99` picks the hashing rule by trial-decoding
attacker-supplied bytes instead of from the chain's own fork schedule, and
`VanityData` is an unbounded `[]byte` that no verification path bounds or
inspects. Either half alone is enough to fix it:

- Select the filter from chain config (which consensus format this block height
  uses), never by guessing from `header.Extra` contents.
- Reject any header whose `VanityData` is not exactly `IstanbulExtraVanity` (32)
  bytes in `Engine.verifyHeader`. The only writers
  (`consensus/istanbul/engine/engine.go:684`, `core/genesis.go:429`,
  `consensus/istanbul/testutils/genesis.go:49`) all pad to exactly 32, so this
  cannot invalidate any historical block.

The second is the smaller change and also removes the unbounded-vanity growth
surface. Doing both is better: the format guess is the actual defect, and a
config-driven filter stops any future variant of this trick.
