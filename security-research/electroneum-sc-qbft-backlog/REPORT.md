# QBFT backlog byte budget counts encoded bytes but retains decoded objects — f validators OOM-kill a node with 128 MiB of traffic

## Summary

QBFT is defined as surviving `f = (N-1)/3` Byzantine validators. Using exactly
that many — no more capability than the protocol already assumes it will
tolerate — I OOM-kill a node with 128 MiB of signed traffic. The backlog in
`consensus/istanbul/core/backlog.go` charges `len(data)`, the encoded wire size,
but stores the decoded message: a `*types.Block` whose transaction slice is
unbounded and eagerly materialised. A minimally-encoded legacy transaction is 10
wire bytes and ~386 bytes of resident heap, so the budget under-counts what it
retains by x38.5. Every admission check passes; nothing is evaded. On a node
given a 4 GiB memory allowance the process is killed by the OOM killer, and the
same binary with the fix applied survives the identical run.

## Relationship to PR #82

This is not the bug PR #82 fixed, and the patch in that PR does not affect it.
#82 added `MaxFuturePreprepareBytes` (4 MiB per message) and the 32 MiB /
512 MiB byte budgets, and those work correctly against the quantity they
measure — encoded wire bytes. The defect is that the quantity they measure is
not the quantity they claim to bound. #82's own commit message states the goal:

> This tracks retained bytes per validator and globally and rejects admission
> once either budget is hit, so **aggregate memory is actually bounded** rather
> than just the worst single message.

Aggregate memory is not bounded. Every message in this PoC is admitted by every
check #82 added. The fix for #82's bug and the fix for this one are different
changes to different lines.

## Setup

- electroneum-sc at commit `17c6ffe` — the merge of PR #82, HEAD of `master` at
  time of testing
- Go 1.19+, `git`, and a Linux host with a cgroup v1 `memory` controller for the
  OOM step
- ~2 GB free RAM for the main proof, ~8 GB for the fault-budget step
- `f` validator private keys. In the PoC the validator set is generated locally
  by the project's own `testutils.GenesisAndKeys`.
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

2. **Step 1 of the run** measures the primitive. The engine in `poc/hunt/` builds
   QBFT messages byte-by-byte rather than encoding Go structs, so it emits the
   smallest legal encoding the decoder will still materialise in full. A minimal
   legacy transaction is the 10-byte RLP list `c9 80 80 80 80 80 80 80 80 80`.

   ```
   legacy-min       marginal: 10 encoded bytes -> 386 heap bytes  (x38.7)
   priority-min     marginal: 18 encoded bytes -> 610 heap bytes  (x33.9)
   dynfee-min       marginal: 15 encoded bytes -> 482 heap bytes  (x32.2)
   accesslist-min   marginal: 14 encoded bytes -> 450 heap bytes  (x32.2)

   legacy-min  ntx=419371  encoded=4.00 MiB  retained=153.94 MiB  amplification=x38.5
   ```

   One PRE-PREPARE sized to 4.00 MiB — just under `MaxFuturePreprepareBytes`, so
   the per-message ceiling admits it — retains 153.94 MiB.

3. **Step 2** drives the real message ingress: `core.handleEncodedMsg`, the
   function `core.handleEvents` dispatches `istanbul.MessageEvent` to. The frames
   traverse `qbfttypes.Decode` → `verifySignatures` → `checkMessage` →
   `addToBacklog` in production order, each signed exactly as the node signs its
   own: `crypto.Sign(crypto.Keccak256(EncodePayloadForSigning()), key)`. Eight
   frames of 4.00 MiB fill `MaxBacklogBytesPerValidator` (32 MiB) exactly.

   ```
   === E2E: SIGNED PRE-PREPARE THROUGH THE REAL INGRESS ===
     attacker  : validator 0xa060B089 (1 of 4, within QBFT's fault budget)
     frames    : 8 x 4.00 MiB, each signed and ecrecovered to a known validator
     charged   :    32.00 MiB   (per-sender budget 32 MiB)
     resident  :  1231.58 MiB
     amplified : x38.5

   E2E BUDGET BYPASS: 1231.58 MiB resident against a 32 MiB per-sender budget (x38.5)
   ```

   The test asserts resident heap stays within the documented budget, so the
   failure line **is** the finding.

4. The same step runs the negative control, proving the signature path executed
   rather than being skipped:

   ```
   --- PASS: TestE2E_ForgedSignatureIsRejected
   [control] non-validator signature rejected; backlog untouched
   ```

   An identical payload signed by a non-validator key is rejected and the backlog
   stays empty.

5. **Step 3** repeats the attack against a live node with nothing stubbed: a real
   `Backend` on a real `BlockChain` with a running QBFT core, driven only through
   `Backend.HandleMsg` with p2p frames.

   ```
   === E2E FULL STACK: p2p frame -> live QBFT node ===
     frames delivered  : 8 via Backend.HandleMsg
     bytes on the wire :    32.00 MiB   (per-sender budget 32 MiB)
     heap resident     :  1231.58 MiB
     amplification     : x38.5
   ```

   Validator addresses differ per run; the set is generated freshly each time.

6. **Step 4** — scale to the fault budget with `--full`:

   ```bash
   ./reproduce.sh --full
   ```

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

7. **Step 5 — the OOM.** Run the same attack against a node whose consensus
   process is given a 4 GiB memory allowance:

   ```bash
   sudo ./oom.sh 4294967296
   ```

   Expected: the process is killed by the kernel OOM killer.

   ```
   === RUN   TestE2E_WithinByzantineFaultBudget
   Killed
   EXIT=137
   cgroup memory.failcnt      : 183
   cgroup memory.max_usage    : 4096 MiB
   ```

8. Control for step 7 — the identical test binary, identical 4 GiB limit, with
   the attached fix applied:

   ```bash
   sudo ./oom.sh 4294967296 --fix
   ```

   ```
   [MITIGATED] only 0/32 frames retained; resident=0.01 MiB
   --- SKIP: TestE2E_WithinByzantineFaultBudget
   PASS
   EXIT=0
   ```

   Same binary, same limit, same traffic: killed without the fix, survives with
   it. The OOM is caused by the amplification, not by the harness.

## Impact

Four Byzantine validators in a 13-validator network — exactly `f = (N-1)/3`, the
faults QBFT is defined as surviving — send 128 MiB of signed consensus traffic
and the receiving node is killed by the OOM killer at a 4 GiB memory allowance.
The node's own accounting reports 25% of its 512 MiB budget in use at the moment
it dies. A single validator reaches 1231.58 MiB from 32.00 MiB of traffic. This
is not a one-shot spike: `MaxFutureSequenceGap = 32` gives a 32-sequence-wide
future window that slides forward as the chain advances, so there is always a
valid future sequence to refill with and the backlog stays full for as long as
the attacker keeps sending. An OOM-killed validator is a validator out of quorum;
`f` of them dying together is the exact condition QBFT is supposed to tolerate.

All figures are measured — heap on a running node, and a kernel OOM kill with a
matched control. I did not demonstrate a consensus safety violation, a chain
split, or any effect on funds; this is availability. The 4 MiB per-message
ceiling and both byte budgets are enforced correctly against the quantity they
measure — none of them is evaded.

## Root cause

`consensus/istanbul/core/handler.go:201` charges the backlog `len(data)`, the
encoded wire size, and `backlog.go:324` stores the decoded message under that
charge. `Preprepare.DecodeRLP` materialises `Proposal *types.Block` with an
unbounded `Txs []*Transaction`, and each minimally-encoded transaction costs
~386 bytes of heap for 10 wire bytes. The transactions are not validated until
`backend.Verify(proposal)`, long after the message is resident, so nothing in the
payload has to be well-formed. `carriesBlockProposal()` already recognises that
ROUND-CHANGE carries a block too, and it amplifies identically.

Fix: charge the budget in the unit it bounds. The attached
`retention-accounting.patch` adds `retentionCost()`, which adds the structural
cost of the decoded block and justification arrays to `encodedSize`, applied at
the top of `addToBacklog`. It never returns less than `encodedSize`, so it is a
strict tightening. A cleaner alternative is to store the raw wire bytes in the
backlog and decode lazily on drain, which makes charged and retained bytes the
same quantity by construction.

The existing tests miss this because they only exercise the budget with payload
carried in a flat `Header.Extra` byte slice, where encoded and resident size are
1:1.
