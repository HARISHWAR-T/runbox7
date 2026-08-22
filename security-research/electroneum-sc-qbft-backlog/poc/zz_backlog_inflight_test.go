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

// muxBackend is commitCaptureBackend with a *stable* event mux, so a test can
// observe what happens to messages that processBacklog hands off while the
// handler loop is busy (the mux subscription channel is unbuffered).
type muxBackend struct {
	*commitCaptureBackend
	mux *event.TypeMux
}

func (b *muxBackend) EventMux() *event.TypeMux { return b.mux }

// TestBacklogByteBudget_InFlightMessagesAreUncounted shows that the byte budget
// bounds *queue residency*, not retention.
//
// processBacklog pops an entry, decrements backlogsBytesTotal/backlogsBytes, and
// then hands the message to `go c.sendEvent(event)`. The mux subscription channel
// is unbuffered (event/event.go newsub), so while the single handler loop is busy
// those goroutines block holding a fully-decoded message alive. The counters have
// already been zeroed, so the budget reports an empty backlog while the memory is
// still resident -- and the same sender can immediately re-fill its entire
// per-validator budget.
//
// Repeating this cycle makes retained memory unbounded, independent of the
// amplification factor.
func TestBacklogByteBudget_InFlightMessagesAreUncounted(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	mux := new(event.TypeMux)
	// Subscribe but never read: this models the handler loop being busy, which is
	// exactly the state it is in while validating a large proposal.
	sub := mux.Subscribe(backlogEvent{})
	defer sub.Unsubscribe()
	c.backend = &muxBackend{commitCaptureBackend: &commitCaptureBackend{}, mux: mux}

	const msgSize = MaxFuturePreprepareBytes
	perRound := MaxBacklogBytesPerValidator / msgSize

	// Every message shares one future view (seq 2, round 0). That matters: when
	// the chain reaches exactly that view, checkMessage returns nil for all of
	// them, so processBacklog POSTS them rather than discarding them as old.
	fillOnce := func() int {
		before := c.backlogsTotal
		for i := 0; i < perRound; i++ {
			admit(t, c, buildWire(2, msgSize), src)
		}
		return c.backlogsTotal - before
	}

	base := heapNow()

	// Round 0: fill the sender's entire per-validator byte budget.
	if n := fillOnce(); n != perRound {
		fmt.Printf("\n[MITIGATED] only %d/%d amplifying payloads admitted\n\n", n, perRound)
		t.Skip("retention accounting rejects the amplifying payload; attack precondition not met")
	}
	chargedAfterFill := c.backlogsBytes[src]
	afterFill := heapNow()

	// Chain progresses: every backlogged message becomes deliverable, so
	// processBacklog pops them all and hands them to goroutines.
	c.current = newRoundState(
		&istanbul.View{Sequence: big.NewInt(2), Round: big.NewInt(0)},
		valSet, nil, nil, nil, nil, func(common.Hash) bool { return false },
	)
	c.state = StateAcceptRequest
	c.processBacklog()

	// Let the handoff goroutines reach their blocking send.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() < perRound && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	chargedAfterDrain := c.backlogsBytesTotal
	afterDrain := heapNow()

	fmt.Printf("\n=== IN-FLIGHT MESSAGES ARE UNCOUNTED ===\n")
	fmt.Printf("  after filling budget : charged=%6.2f MiB   heap=%8.2f MiB\n",
		mib(uint64(chargedAfterFill)), mib(afterFill-base))
	fmt.Printf("  after processBacklog : charged=%6.2f MiB   heap=%8.2f MiB   goroutines=%d\n",
		mib(uint64(chargedAfterDrain)), mib(afterDrain-base), runtime.NumGoroutine())

	if chargedAfterDrain != 0 {
		t.Fatalf("expected the counters to be zeroed by the drain, got %d", chargedAfterDrain)
	}

	// The budget now reads empty, so the *same* sender can re-fill it in full
	// even though none of the previous round has actually been released.
	refilled := fillOnce()
	chargedAfterRefill := c.backlogsBytes[src]
	afterRefill := heapNow()

	fmt.Printf("  after re-filling     : charged=%6.2f MiB   heap=%8.2f MiB   (%d/%d re-admitted)\n",
		mib(uint64(chargedAfterRefill)), mib(afterRefill-base), refilled, perRound)
	fmt.Printf("  budget cap for this sender: %.0f MiB\n\n", mib(MaxBacklogBytesPerValidator))

	runtime.KeepAlive(c)

	resident := afterRefill - base
	if resident > uint64(MaxBacklogBytesPerValidator) {
		t.Errorf("RESIDENCY UNBOUNDED: %.2f MiB resident for one sender whose budget is %.0f MiB; "+
			"the drained round is still held by in-flight goroutines but is no longer charged",
			mib(resident), mib(MaxBacklogBytesPerValidator))
	}
}
