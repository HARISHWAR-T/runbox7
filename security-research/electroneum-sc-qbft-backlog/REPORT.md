# QBFT future-message backlog charges a byte budget in encoded wire bytes but retains decoded objects — one validator pins 1.2 GB from a 32 MiB budget

## Summary

As one validator in a QBFT network, I send 32.00 MiB of signed PRE-PREPARE
frames — exactly my per-sender backlog budget — and the receiving node retains
1231.58 MiB of heap for them. The backlog in `consensus/istanbul/core/backlog.go`
charges `len(data)`, the encoded wire size, but stores the decoded message: a
`*types.Block` whose transaction slice is unbounded and eagerly materialised. A
minimally-encoded legacy transaction is 10 wire bytes and ~386 bytes of resident
heap, so the budget under-counts what it retains by x38.5. Every admission check
in `addToBacklog` passes; nothing is bypassed, the accounting is just measuring
the wrong quantity.

## Setup

- electroneum-sc at commit `17c6ffe` (HEAD of `master` at time of testing)
- Go 1.19+ and `git`
- ~2 GB free RAM for the main proof, ~8 GB for the fault-budget step
- One validator private key. In the PoC the validator set is generated locally by
  the project's own `testutils.GenesisAndKeys`, and the attacker uses a key from
  that set that is not the node's own.
- Attached: `electroneum-qbft-backlog-poc.zip`

Everything runs against a local in-memory test chain. No Electroneum host is
contacted; the only network access is `git clone` of the public repository.

## Steps to reproduce

1. Unpack the attachment and run the driver. It clones the target, pins it to
   `17c6ffe`, installs the PoC, and runs every step.

   ```bash
   unzip electroneum-qbft-backlog-poc.zip
   cd electroneum-qbft-backlog-poc
   ./reproduce.sh
   ```

   Expected: the target pins to `17c6ffe30 — Merge pull request #82 from
   electroneum/fix-qbft-backlog-byte-limit`.

2. **Step 1 of the run** measures the amplification primitive. The engine in
   `poc/hunt/` builds QBFT messages byte-by-byte instead of encoding Go structs,
   so it emits the smallest legal encoding the decoder will still materialise in
   full. A minimal legacy transaction is the 10-byte RLP list `c9 80 80 80 80 80
   80 80 80 80`.

   Expected output:

   ```
   legacy-min       marginal: 10 encoded bytes -> 386 heap bytes  (x38.7)
   priority-min     marginal: 18 encoded bytes -> 610 heap bytes  (x33.9)
   dynfee-min       marginal: 15 encoded bytes -> 482 heap bytes  (x32.2)
   accesslist-min   marginal: 14 encoded bytes -> 450 heap bytes  (x32.2)

   legacy-min  ntx=419371  encoded=4.00 MiB  retained=153.94 MiB  amplification=x38.5
   ```

   One PRE-PREPARE sized to 4.00 MiB — just under `MaxFuturePreprepareBytes`, so
   the per-message ceiling admits it — retains 153.94 MiB.

3. **Step 2 of the run** drives the real message ingress. It enters at
   `core.handleEncodedMsg`, the function `core.handleEvents` dispatches
   `istanbul.MessageEvent` to, so the frames traverse `qbfttypes.Decode` →
   `verifySignatures` → `checkMessage` → `addToBacklog` in production order. Each
   frame is signed with a validator key exactly as the node signs its own:
   `crypto.Sign(crypto.Keccak256(EncodePayloadForSigning()), key)`.

   Eight frames of 4.00 MiB are sent, filling `MaxBacklogBytesPerValidator`
   (32 MiB) exactly.

   Expected output:

   ```
   === E2E: SIGNED PRE-PREPARE THROUGH THE REAL INGRESS ===
     path      : handleEncodedMsg -> Decode -> verifySignatures -> checkMessage -> addToBacklog
     attacker  : validator 0xa060B089 (1 of 4, within QBFT's fault budget)
     frames    : 8 x 4.00 MiB, each signed and ecrecovered to a known validator
     charged   :    32.00 MiB   (per-sender budget 32 MiB)
     resident  :  1231.58 MiB
     amplified : x38.5

   E2E BUDGET BYPASS: 1231.58 MiB resident against a 32 MiB per-sender budget (x38.5)
   ```

   The test asserts that resident heap stays within the documented budget, so the
   failure line **is** the finding.

4. The same step runs the negative control, which proves the signature path
   actually executed rather than being skipped:

   ```
   --- PASS: TestE2E_ForgedSignatureIsRejected
   [control] non-validator signature rejected; backlog untouched
   ```

   An identical payload signed by a non-validator key is rejected and the backlog
   stays empty. The 1231.58 MiB in step 3 is therefore reached only by a frame
   whose signature ecrecovered to a member of the validator set.

5. **Step 3 of the run** repeats the attack against a live node with nothing
   stubbed. A real `Backend` is stood up on a real `BlockChain` with a real
   4-validator set and a running QBFT core (`Backend.Start` → `startQBFT` →
   `core.Start` → `handleEvents`). The only entry point used is
   `Backend.HandleMsg`, which is what the eth protocol handler calls for a
   consensus frame from a connected peer.

   Expected output:

   ```
   === E2E FULL STACK: p2p frame -> live QBFT node ===
     node under attack : 0x8bA6300112 (validator set of 4)
     attacker          : 0x1EC8Db6601 (holds 1 validator key)
     frames delivered  : 8 via Backend.HandleMsg
     bytes on the wire :    32.00 MiB   (per-sender budget 32 MiB)
     heap resident     :  1231.58 MiB
     amplification     : x38.5

   E2E FULL-STACK BYPASS: 1231.58 MiB resident on a live node from 32.00 MiB of
   wire traffic sent by one validator whose backlog budget is 32 MiB
   ```

   Validator addresses differ per run; the set is generated freshly each time.

6. **Step 4** — run it again with `--full` to scale to the number of faulty
   validators QBFT already tolerates, `f = (N-1)/3`:

   ```bash
   ./reproduce.sh --full
   ```

   Expected output:

   ```
   === E2E: SCALED TO THE BYZANTINE FAULT BUDGET ===
     validator set        : N=13, tolerated faults f=4
     Byzantine validators : 4 (exactly f)
     frames admitted      : 32, all signature-verified
     global byte budget   :   512.00 MiB
     charged              :   128.00 MiB  (25% of the global budget)
     resident             :  4926.29 MiB
     amplification        : x38.5
   ```

   The node holds 4926.29 MiB while its own accounting reports 128 MiB of a
   512 MiB budget used.

7. Confirm the diagnosis by re-running with the attached fix, which charges the
   budget in estimated resident heap instead of wire size:

   ```bash
   ./reproduce.sh --fix
   ```

   Expected: the same frames are no longer admitted (`0/8` and `0/32` retained),
   the full-stack resident heap drops to ~0.02 MiB, and the project's own suite
   (step 5, PoC tests excluded) stays green — as it also does unpatched, so the
   PoC files themselves change nothing.

## Impact

A single validator forces every peer that receives its messages to hold 1231.58 MiB
of heap for 32.00 MiB of traffic, and the node's own memory accounting reports
that it is exactly at its 32 MiB per-sender limit while doing so. Scaled to
`f = (N-1)/3` — the faults QBFT is designed to survive — 4 Byzantine validators in
a 13-validator network drive a correct node to 4926.29 MiB resident while the
global byte budget reports 25% utilisation. Both figures are measured heap on a
running node, reproduced three ways: through the real message ingress, through
`Backend.HandleMsg` on a live chain, and at fault-budget scale. The memory a
correct node is forced to hold is set by the fault budget the protocol already
assumes, so no capability beyond a single validator key is needed.

This is availability only. I did not demonstrate an OOM kill, a consensus safety
violation, chain split, or any effect on funds — I measured retained heap and
budget accounting, nothing further. The 4 MiB per-message ceiling and both byte
budgets are enforced correctly against the quantity they measure; none of them is
evaded.

## Root cause

`consensus/istanbul/core/handler.go:201` charges the backlog `len(data)`, the
encoded wire size, and `backlog.go:324` stores the decoded message under that
charge. For RLP those are not proportional: `Preprepare.DecodeRLP` materialises
`Proposal *types.Block` with an unbounded `Txs []*Transaction`, and each
minimally-encoded transaction costs ~386 bytes of heap for 10 wire bytes. The
transactions are not validated until `backend.Verify(proposal)`, long after the
message is resident, so nothing in the payload has to be well-formed.

Fix: charge the budget in the unit it is bounding. The attached
`retention-accounting.patch` adds a `retentionCost()` that adds the structural
cost of the decoded block and justification arrays to `encodedSize`, applied at
the top of `addToBacklog`. It never returns less than `encodedSize`, so it is a
strict tightening. A cleaner alternative is to store the raw wire bytes in the
backlog and decode lazily on drain, which makes charged and retained bytes the
same quantity by construction.

The existing tests miss this because they only exercise the budget with payload
carried in a flat `Header.Extra` byte slice, where encoded and resident size are
1:1.
