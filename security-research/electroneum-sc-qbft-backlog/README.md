# electroneum-sc — QBFT backlog byte budget is charged in the wrong unit

**Target:** https://github.com/electroneum/electroneum-sc @ `17c6ffe`
**Component:** `consensus/istanbul/core/backlog.go`
**Class:** Resource-exhaustion / remote DoS (memory)
**Attacker:** one Byzantine validator (within QBFT's `f` fault budget)
**Status:** reproduced end-to-end on a live node, root-caused, candidate fix implemented and verified

---

## 1. The control under test

PRs #78–#82 hardened the QBFT future-message backlog against a memory DoS. The
series added, in order:

| Constant | Value | Stated purpose |
|---|---|---|
| `MaxFuturePreprepareBytes` | 4 MiB | ceiling on a single block-bearing message |
| `MaxBacklogBytesPerValidator` | 32 MiB | per-sender retained-byte budget |
| `MinBacklogBytesTotal` | 128 MiB | global floor |
| `MaxBacklogBytesTotalCeiling` | 512 MiB | global ceiling, *"kept comfortably below any validator's RAM"* |

The commit message for `a340b8f` states the security property directly:

> This tracks retained bytes per validator and globally and rejects admission
> once either budget is hit, **so aggregate memory is actually bounded** rather
> than just the worst single message.

That claim is what this research targeted.

## 2. Root cause

The budget is charged in **encoded wire bytes**, but what the backlog retains is
the **decoded Go object graph**.

`handler.go:201` charges `len(data)`:

```go
// len(data) is the true encoded wire size of this message. We carry it into
// the backlog so future-message admission can charge a byte budget [...]
return c.handleDecodedMessage(m, len(data))
```

`backlog.go` then stores the *decoded* message under that charge:

```go
backlog.Push(&backlogEntry{msg: msg, size: encodedSize}, ...)
c.backlogsBytes[src]    += encodedSize
c.backlogsBytesTotal    += encodedSize
```

For RLP these two quantities are not proportional. A `Preprepare` decodes
`Proposal *types.Block`, whose `Txs []*Transaction` is unbounded and eagerly
materialised. A minimally-encoded legacy transaction —

```
c9 80 80 80 80 80 80 80 80 80      # 10 bytes on the wire
```

— decodes into a `types.Transaction` (interface word, `time.Time`, four
`atomic.Value` caches), a `LegacyTx`, and one heap-allocated `*big.Int` per
numeric field. **10 wire bytes → ~386 bytes of resident heap.**

Nothing in the message needs to be *valid*. Transactions are only checked in
`backend.Verify(proposal)`, which runs in `handlePreprepareMsg` — long after
the message has been admitted to the backlog and is resident.

## 3. Measured amplification

`engine/` generates QBFT wire payloads from a genome and scores
decoded-heap-per-encoded-byte. Marginal cost per transaction, measured:

| tx encoding | wire bytes | resident heap | amplification |
|---|---|---|---|
| **legacy (minimal)** | **10** | **386** | **x38.7** |
| priority (`0x40`, Electroneum-specific) | 18 | 610 | x33.9 |
| dynamic-fee (`0x02`) | 15 | 482 | x32.2 |
| access-list (`0x01`) | 14 | 450 | x32.2 |

Whole-message, sized to sit *just under* the 4 MiB per-message ceiling so every
admission check passes:

```
legacy-min  ntx=419371  encoded=4.00 MiB  retained=153.94 MiB  x38.5
```

## 4. Impact

Driving the real `addToBacklog` (`poc/zz_backlog_amplification_test.go`):

```
messages admitted        : 8 (each 4.00 MiB encoded, at the per-message ceiling)
budget believes retained :    32.00 MiB  (cap for this sender: 32 MiB)
actually retained on heap:  1231.58 MiB
amplification            : x38.5
```

One validator, entirely inside its own per-sender budget, pins **1.2 GB**.
Projected onto the global budget the design calls *"comfortably below any
validator's RAM"*:

| budget | charged | actually resident |
|---|---|---|
| per-validator | 32 MiB | **1,231 MiB** |
| global floor | 128 MiB | **4,926 MiB** |
| global ceiling | 512 MiB | **19,706 MiB** |

### 4.1 Second gap: the budget only covers *queue residency*

`processBacklog` decrements the counters and then hands the message off:

```go
c.backlogsTotal--
c.backlogsBytesTotal   -= entry.size
c.backlogsBytes[src]   -= entry.size
...
go c.sendEvent(event)          // backlog.go:408
```

The mux subscription channel is unbuffered (`event/event.go`, `newsub`), so
while the single `handleEvents` consumer is busy, those goroutines block holding
a fully decoded message alive — **after** it has been un-charged. The budget
reads empty while the memory is still resident, and the sender can re-fill it.

`poc/zz_backlog_unbounded_test.go`, six fill/drain cycles:

```
cycle  charged (MiB)    resident (MiB)   goroutines
1      32.00            1231.55          10
2      32.00            2463.09          18
3      32.00            3694.64          26
4      32.00            4926.18          34
5      32.00            6157.72          42
6      32.00            7389.27          50
```

Linear growth; the charged budget never exceeds 32 MiB.

This is the *same pattern* the project already identified and fixed one layer
up. Commit `8219bb7` ("deliver consensus messages synchronously to apply
backpressure") replaced a detached `go Post` at the p2p ingress, with this
rationale in `backend/handler.go`:

> A detached `go Post` here lets a remote peer enqueue consensus frames faster
> than `core.handleEvents` drains them, **accumulating unbounded blocked
> goroutines that each pin a full payload in heap until the node OOMs.**

`backlog.go:408` is the same construct, unfixed.

**Caveat, stated honestly:** `processBacklog` runs only on the `handleEvents`
goroutine, so in production a new drain cannot begin while the previous batch is
still blocking. The clean per-cycle linearity above is driven by the harness
calling `addToBacklog` out-of-band. The production consequence is bounded but
still wrong: one drained batch (~1.2 GB) stays resident and uncharged while the
sender re-fills the budget (~1.2 GB), so a single validator holds **~2.4 GB
against a 32 MiB budget** rather than growing without limit. Finding 4.1 is an
accounting gap that roughly doubles Finding 3; Finding 3 is the x38.5 multiplier
and is the primary issue.

## 4bis. End-to-end verification

The measurements in §4 drive `addToBacklog` directly. The tests below instead go
through the production path with genuine ECDSA signatures, so nothing is stubbed
and no internal is poked. Only one attacker capability is assumed: possession of
a single validator private key.

### (a) Real ingress — `poc/zz_e2e_signed_test.go`

Enters at `handleEncodedMsg`, the exact function `core.handleEvents` dispatches
`istanbul.MessageEvent` to. Traverses, in production order: `qbfttypes.Decode`
→ `verifySignatures` (real ecrecover) → `checkMessage` → `addToBacklog`.

```
attacker  : validator 0xa060B089 (1 of 4, within QBFT's fault budget)
frames    : 8 x 4.00 MiB, each signed and ecrecovered to a known validator
charged   :    32.00 MiB   (per-sender budget 32 MiB)
resident  :  1231.58 MiB
amplified : x38.5
```

**Negative control** (`TestE2E_ForgedSignatureIsRejected`): the identical payload
signed by a non-validator key is rejected and the backlog is untouched. Without
this control the result above could be explained by the signature check simply
not running.

### (b) Full stack — `poc/backend/zz_e2e_fullstack_test.go`

A real `Backend` on a real `BlockChain` with a real 4-validator set and a live
QBFT core (`Backend.Start` → `startQBFT` → `core.Start` → `handleEvents`). The
attacker sends ordinary p2p frames; the only entry point used is
`Backend.HandleMsg`, which is what the eth protocol handler calls for a consensus
frame from any connected peer.

```
node under attack : 0x8bA6300112 (validator set of 4)
attacker          : 0x1EC8Db6601 (holds 1 validator key)
frames delivered  : 8 via Backend.HandleMsg
bytes on the wire :    32.00 MiB   (per-sender budget 32 MiB)
heap resident     :  1231.58 MiB
amplification     : x38.5
```

### (c) Scaled to the Byzantine fault budget — `poc/zz_e2e_faultbudget_test.go`

QBFT tolerates `f = (N-1)/3` faulty validators. Each fills its own 32 MiB
per-sender budget; `f × 32 MiB` stays well inside the global budget, so every
frame is admitted.

```
validator set        : N=13, tolerated faults f=4
Byzantine validators : 4 (exactly f — the protocol promises to survive this)
frames admitted      : 32, all signature-verified
global byte budget   :   512.00 MiB
charged              :   128.00 MiB  (25% of the global budget)
resident             :  4926.29 MiB
amplification        : x38.5
```

**This is the severity argument.** The node is holding 4.9 GB while its own
memory accounting reports it is at a quarter of budget. The amount of memory a
correct node is forced to hold is set by the fault budget the protocol already
promises to survive — so no additional attacker capability is needed beyond what
QBFT already assumes. At `N=49` (`f=16`) the attackers saturate the 512 MiB
global ceiling, which is ~19.7 GB resident.

## 5. Why the existing tests miss it

`backlog_byte_limit_test.go` exercises the budget with

```go
block := types.NewBlockWithHeader(&types.Header{Number: ..., Extra: extra})
```

— payload carried in a flat `Extra []byte`, where encoded size and resident size
are 1:1. The control is only ever measured with a non-amplifying payload, so the
unit mismatch is invisible.

`TestProcessBacklog_ByteAccountingIsExact` asserts the counters return to zero
after a drain and calls that "exact". It also comments that the messages are
"popped and posted rather than requeued" — but it advances the view to sequence
100, so `checkMessage` returns `errOldMessage` and the messages are *discarded*,
never posted. The posting path (`go c.sendEvent`) is not covered by that test at
all.

## 6. Candidate fix

`retention-accounting.patch` charges the budgets in the unit they are meant to
bound — estimated resident heap rather than wire size:

```go
func retentionCost(msg qbfttypes.QBFTMessage, encodedSize int) int {
	cost := encodedSize
	switch m := msg.(type) {
	case *qbfttypes.Preprepare:
		cost += structural(m.Proposal)
		cost += (len(m.JustificationPrepares) +
			len(m.JustificationRoundChanges)) * heapPerJustification
	case *qbfttypes.RoundChange:
		cost += structural(m.PreparedBlock)
	}
	return cost
}
```

Applied at the top of `addToBacklog`, before every existing check. It never
returns less than `encodedSize`, so it is a strict tightening.

Verified:

| | unpatched | patched |
|---|---|---|
| amplifying payloads admitted (direct) | 8 / 8 | **0 / 8** |
| signed frames retained (real ingress) | 8 / 8 | **0 / 8** |
| frames retained at `f` faults (N=13) | 32 / 32 | **0 / 32** |
| resident, full stack via `HandleMsg` | 1231.58 MiB | **0.02 MiB** |
| 6-cycle growth | 7,389 MiB | **0.00 MiB** |
| electroneum-sc `consensus/istanbul/...` suite | pass | **pass, no regressions** |

Headroom for legitimate blocks is preserved: gas bounds a real block to
~1,428 minimal transactions (30M / 21,000), costing ~548 KB of retention charge
against a 4 MiB ceiling.

A structurally cleaner alternative — worth considering over the estimate above —
is to **store the raw wire bytes in the backlog and decode lazily on drain**.
Then "encoded bytes" and "retained bytes" are the same quantity by construction
and no heuristic constant is needed.

For 4.1, apply the `8219bb7` treatment to `backlog.go:408`: deliver
synchronously, or keep the entry charged until the event is actually consumed.

## 7. Reproducing

```bash
git clone https://github.com/electroneum/electroneum-sc.git && cd electroneum-sc
git checkout 17c6ffe

cp -r <this>/engine hunt                        # payload engine
cp <this>/poc/zz_*.go         consensus/istanbul/core/
cp <this>/poc/backend/zz_*.go consensus/istanbul/backend/

go run ./hunt/cmd/amp                           # amplification table
go test ./consensus/istanbul/core/    -run TestBacklogByteBudget -v -timeout 20m
go test ./consensus/istanbul/core/    -run TestE2E_ -v -timeout 20m   # real ingress + fault budget
go test ./consensus/istanbul/backend/ -run TestE2E_FullStack -v       # live node via HandleMsg

git apply <this>/retention-accounting.patch     # then re-run: attack blocked
```

Needs ~10 GB RAM for the 6-cycle test and ~6 GB for the fault-budget test. Entirely local; no network, no chain
state, no production system involved.
