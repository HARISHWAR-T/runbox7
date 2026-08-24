# QBFT backlog byte budget stops counting a message at pop, not at release — one sender holds twice its budget

## Summary

The QBFT backlog charges a per-sender byte budget to bound how much future-message
memory one validator can pin. `processBacklog` decrements those counters the
moment it pops an entry, then hands the message to a detached goroutine. The mux
subscription channel is unbuffered, so while the single `handleEvents` consumer is
busy that goroutine sits blocked holding a fully decoded message alive — after its
bytes have already been un-charged. The budget reports the memory as freed, and
the same sender is immediately re-admitted for its full budget. Measured: 32 MiB
charged, 64 MiB resident, one sender. This reproduces with flat payloads, so it is
an accounting bug and not an amplification one.

## Root cause

`consensus/istanbul/core/backlog.go:366-368`, inside `processBacklog`'s drain loop:

```go
m, prio := backlog.Pop()
entry := m.(*backlogEntry)
c.backlogsTotal--
c.backlogsBytesTotal -= entry.size
c.backlogsBytes[srcAddress] -= entry.size
```

and then, 40 lines later at `backlog.go:408`:

```go
go c.sendEvent(event)
```

Between those two points the message is not freed. It is handed to a goroutine
that posts to the istanbul mux, whose subscription channel is unbuffered
(`event/event.go:164`, `c := make(chan *TypeMuxEvent)`). While `core.handleEvents`
is busy — which is exactly what it is doing while validating a proposal — that
goroutine blocks on the send, keeping `entry.msg` reachable. Only when
`handleEvents` reaches `case backlogEvent:` (`consensus/istanbul/core/handler.go:129`)
is the message actually consumed.

So the counters track queue residency, not retention. Admission
(`backlog.go:295` and `backlog.go:317`) reads those counters, sees a budget it
believes is free, and admits a fresh batch against memory that has not been
released.

This is the same detached-post shape the project already removed one layer up.
`consensus/istanbul/backend/handler.go:92` explains why, in its own words:

> A detached `go Post` here lets a remote peer
> enqueue consensus frames faster than core.handleEvents drains them,
> accumulating unbounded blocked goroutines that each pin a full payload
> in heap until the node OOMs.

That reasoning applies unchanged at `backlog.go:408`. The ingress was fixed; this
handoff was not.

## Setup

- electroneum-sc at commit `17c6ffe`, HEAD of `master` at time of testing
- Go 1.19+ and `git`
- ~200 MB free RAM
- No keys and no privileges beyond being a validator whose messages reach the
  backlog at all
- Attached: `etn-qbft-backlog-inflight-poc.zip`

Runs against local in-memory structures. No Electroneum host was contacted.

## Steps to reproduce

1. Unpack and run:

   ```bash
   unzip etn-qbft-backlog-inflight-poc.zip
   cd etn-qbft-backlog-inflight-poc
   ./reproduce.sh
   ```

   Expected: `target pinned at 17c6ffe30`.

2. The PoC stands up a core with a real `event.TypeMux` and a subscriber that
   never reads, which models the handler loop being busy. It then fills one
   sender's per-sender budget (`MaxBacklogBytesPerValidator` = 32 MiB,
   `backlog.go:80`) with eight 4 MiB messages built by the project's own
   `makeFuturePreprepare` helper — flat `Header.Extra` bytes, so encoded and
   resident size are 1:1.

3. All eight share one future view (sequence 2, round 0). That matters: when the
   chain reaches exactly that view, `checkMessage` returns nil for all of them, so
   `processBacklog` posts them rather than discarding them as old.

4. **Step 1 of the run** advances the view, calls `processBacklog`, and prints the
   counters against the heap:

   ```
   per-sender budget: 32 MiB, 8 messages of 4 MiB

                          charged (MiB)    resident (MiB)
   after fill             32.00            32.04
   after processBacklog   0.00             32.01   (8 goroutines blocked on the unbuffered mux)
   after re-fill          32.00            64.05   (8/8 re-admitted)

   BUDGET STOPS COUNTING TOO EARLY: 64.05 MiB resident for one sender whose
   per-sender budget is 32 MiB.
   --- FAIL: TestBacklogAccounting_InFlightUncharged
   ```

   Read the middle row: charged drops to zero, resident does not move, and eight
   goroutines are parked. The test asserts resident memory stays within the
   budget, so the failure is the finding.

5. **Steps 2 and 3** run the upstream `consensus/istanbul/...` suite with the PoC
   excluded, and then the project's own `TestProcessBacklog_*` and
   `TestAddToBacklog_*` tests by name, so the fix below can be checked against
   them. Both are green.

6. Confirm the diagnosis:

   ```bash
   ./reproduce.sh --fix
   ```

   Expected: `0/8 re-admitted`, resident stays at 32.05 MiB instead of 64.05, the
   test reports `[MITIGATED]` and skips, and steps 2 and 3 remain green.

## Impact

A validator whose per-sender budget is 32 MiB holds 64 MiB. The budget exists to
bound exactly that number, and it is wrong by a factor of two for as long as the
consumer is busy — which is precisely when the bound matters, because a busy
consumer is what lets the backlog fill in the first place.

The effect compounds with anything that raises the cost of a backlogged message,
since the doubling applies to whatever is actually resident rather than to the
32 MiB the counters believe.

### What this is not

I am not claiming unbounded growth. `processBacklog` runs only on the
`handleEvents` goroutine, so a second drain cannot begin while the first batch is
still blocking — the uncharged set is one drained batch, not an ever-growing one.
An earlier version of this harness produced linear multi-GB growth by calling
`addToBacklog` out of band, which no real peer can do; that number was an artifact
and is not claimed here. The honest figure is the measured one: 2x, one batch.

The project's own `TestProcessBacklog_ByteAccountingIsExact`
(`consensus/istanbul/core/backlog_byte_limit_test.go:162`) asserts the counters
return to zero after a drain and treats that as correct. They do return to zero —
that is the bug, not the proof of correctness. That test advances the view to
sequence 100, so its messages are discarded as `errOldMessage` rather than posted,
and it never exercises the `go c.sendEvent` path at all.

## Fix

Attached as `backlog-charge-until-consumed.patch`. It keeps the bytes charged for
the whole time the message is resident, rather than only while it sits in the
queue:

- `processBacklog` charges the popped entry to a new in-flight counter before
  handing it off, and marks the event `inFlight: true`
- `handleEvents` releases that charge after `handleDecodedMessage` returns — after,
  not before, so that a message which re-backlogs is never charged to neither
  budget during the transition
- both admission checks in `addToBacklog` add the in-flight bytes to what they
  already count

The `inFlight` flag matters: `consensus/istanbul/core/preprepare.go:178` also
posts a `backlogEvent`, from the future-PRE-PREPARE timer. That message was never
popped from a backlog, so releasing a charge for it would underflow the counter.
Only events produced by `processBacklog`'s handoff carry the flag.

Verified: with the patch the sender is re-admitted 0/8 instead of 8/8, resident
memory stays at one budget, and the upstream `consensus/istanbul/...` suite plus
the project's own backlog tests — `TestProcessBacklog_ByteAccountingIsExact`
included — all still pass.

Making the post synchronous, mirroring the ingress fix in `8219bb7`, is not an
option here: `processBacklog` is itself called from the `handleEvents` goroutine
via `setState`, so posting inline to the channel that `handleEvents` reads would
deadlock. Charging until consumption is the equivalent that works at this site.
