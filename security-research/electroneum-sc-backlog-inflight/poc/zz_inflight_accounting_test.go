package core

import (
	"fmt"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	"github.com/electroneum/electroneum-sc/event"
)

// muxBackend is commitCaptureBackend with a STABLE event mux, so a test can watch
// what happens to messages processBacklog hands off while the consumer is busy.
// commitCaptureBackend.EventMux() returns a fresh mux per call, which would make
// every Post go nowhere.
type muxBackend struct {
	*commitCaptureBackend
	mux *event.TypeMux
}

func (b *muxBackend) EventMux() *event.TypeMux { return b.mux }

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func mib(b uint64) float64 { return float64(b) / (1024 * 1024) }

// TestBacklogAccounting_InFlightUncharged shows the backlog byte budget stops
// accounting for a message the moment it is popped, while the message stays
// resident in the handoff goroutine.
//
// processBacklog decrements backlogsTotal / backlogsBytesTotal / backlogsBytes at
// backlog.go:366-368, then hands the message to `go c.sendEvent(event)` at
// backlog.go:408. The mux subscription channel is unbuffered (event/event.go:164),
// so while the single core.handleEvents consumer is busy those goroutines block
// holding a fully decoded message alive -- after it has been un-charged.
//
// Deliberately uses flat Header.Extra payloads, where encoded size and resident
// size are 1:1. This finding is about WHEN the budget stops counting, not about
// how much a decoded message costs, and it reproduces with no amplification at all.
func TestBacklogAccounting_InFlightUncharged(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()
	c.address = valSet.List()[0].Address()

	mux := new(event.TypeMux)
	// Subscribe and never read: this models the handler loop being busy, which is
	// exactly the state it is in while validating a proposal.
	sub := mux.Subscribe(backlogEvent{})
	defer sub.Unsubscribe()
	c.backend = &muxBackend{commitCaptureBackend: &commitCaptureBackend{}, mux: mux}

	const per = 4 * 1024 * 1024 // 4 MiB per message
	nMsgs := MaxBacklogBytesPerValidator / per

	// Every message shares one future view (seq 2, round 0). That matters: when the
	// chain reaches exactly that view, checkMessage returns nil for all of them, so
	// processBacklog POSTS them rather than discarding them as old.
	fill := func() int {
		before := c.backlogsTotal
		for i := 0; i < nMsgs; i++ {
			c.addToBacklog(makeFuturePreprepare(2, 0, src, per), per)
		}
		return c.backlogsTotal - before
	}

	base := heapNow()

	if n := fill(); n != nMsgs {
		t.Fatalf("first fill admitted %d of %d", n, nMsgs)
	}
	chargedAfterFill := c.backlogsBytes[src]
	heapAfterFill := heapNow()

	// Chain reaches that view: every backlogged message becomes deliverable.
	c.current = newRoundState(
		&istanbul.View{Sequence: big.NewInt(2), Round: big.NewInt(0)},
		valSet, nil, nil, nil, nil, func(common.Hash) bool { return false },
	)
	c.state = StateAcceptRequest
	goroutinesBefore := runtime.NumGoroutine()
	c.processBacklog()

	// Let the handoff goroutines reach their blocking send.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() < goroutinesBefore+nMsgs && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	chargedAfterDrain := c.backlogsBytesTotal
	perSrcAfterDrain := c.backlogsBytes[src]
	blocked := runtime.NumGoroutine() - goroutinesBefore
	heapAfterDrain := heapNow()

	// The budget now reads empty, so the SAME sender can re-fill it in full even
	// though none of the previous batch has actually been released.
	refilled := fill()
	chargedAfterRefill := c.backlogsBytes[src]
	heapAfterRefill := heapNow()

	runtime.KeepAlive(c)

	fmt.Printf("\n=== BACKLOG BUDGET STOPS COUNTING AT POP, NOT AT RELEASE ===\n")
	fmt.Printf("  per-sender budget: %.0f MiB, %d messages of %.0f MiB\n\n",
		mib(MaxBacklogBytesPerValidator), nMsgs, mib(per))
	fmt.Printf("  %-22s %-16s %s\n", "", "charged (MiB)", "resident (MiB)")
	fmt.Printf("  %-22s %-16.2f %.2f\n", "after fill", mib(uint64(chargedAfterFill)), mib(heapAfterFill-base))
	fmt.Printf("  %-22s %-16.2f %.2f   (%d goroutines blocked on the unbuffered mux)\n",
		"after processBacklog", mib(uint64(chargedAfterDrain)), mib(heapAfterDrain-base), blocked)
	fmt.Printf("  %-22s %-16.2f %.2f   (%d/%d re-admitted)\n\n",
		"after re-fill", mib(uint64(chargedAfterRefill)), mib(heapAfterRefill-base), refilled, nMsgs)

	if chargedAfterDrain != 0 || perSrcAfterDrain != 0 {
		fmt.Printf("  [MITIGATED] the drain no longer zeroes the counters (total=%d, per-src=%d)\n\n",
			chargedAfterDrain, perSrcAfterDrain)
		t.Skip("in-flight messages are now accounted for")
	}
	if refilled != nMsgs {
		fmt.Printf("  [MITIGATED] only %d/%d re-admitted; the budget accounts for in-flight bytes\n\n",
			refilled, nMsgs)
		t.Skip("in-flight messages are now accounted for")
	}

	resident := heapAfterRefill - base
	t.Errorf("BUDGET STOPS COUNTING TOO EARLY: %.2f MiB resident for one sender whose "+
		"per-sender budget is %.0f MiB. The drained batch is still held by %d blocked "+
		"handoff goroutines but is charged to nobody.",
		mib(resident), mib(MaxBacklogBytesPerValidator), blocked)
}
