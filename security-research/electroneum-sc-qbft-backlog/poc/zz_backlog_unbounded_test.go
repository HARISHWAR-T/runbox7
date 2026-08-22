package core

import (
	"fmt"
	"math/big"
	"runtime"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	"github.com/electroneum/electroneum-sc/event"
)

// TestBacklogByteBudget_UnboundedGrowth repeats the fill/drain cycle and shows
// retained memory growing linearly with the number of cycles while the charged
// byte budget never exceeds its 32 MiB per-sender cap.
//
// One Byzantine validator drives this. Every message passes every admission
// check in addToBacklog.
func TestBacklogByteBudget_UnboundedGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates multiple GiB")
	}
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	mux := new(event.TypeMux)
	sub := mux.Subscribe(backlogEvent{})
	defer sub.Unsubscribe()
	c.backend = &muxBackend{commitCaptureBackend: &commitCaptureBackend{}, mux: mux}

	const msgSize = MaxFuturePreprepareBytes
	perRound := MaxBacklogBytesPerValidator / msgSize
	const cycles = 6

	// Build one wire payload per cycle up front; within a cycle the same bytes are
	// decoded perRound times. Keeps the measured loop about admission, not codegen.
	wires := make([][]byte, cycles+2)
	for i := range wires {
		wires[i] = buildWire(uint64(i), msgSize)
	}

	base := heapNow()
	fmt.Printf("\n=== UNBOUNDED GROWTH: one Byzantine validator, 32 MiB budget ===\n")
	fmt.Printf("  %-6s %-16s %-16s %s\n", "cycle", "charged (MiB)", "resident (MiB)", "goroutines")

	for cycle := 1; cycle <= cycles; cycle++ {
		// Backlog phase: messages for the next view.
		next := int64(1 + cycle)
		c.current = newRoundState(
			&istanbul.View{Sequence: big.NewInt(next - 1), Round: big.NewInt(0)},
			valSet, nil, nil, nil, nil, func(common.Hash) bool { return false },
		)
		c.state = StateAcceptRequest
		for i := 0; i < perRound; i++ {
			admit(t, c, wires[next], src)
		}
		charged := c.backlogsBytes[src]
		if c.backlogsTotal == 0 {
			fmt.Printf("\n[MITIGATED] no amplifying payload admitted at cycle %d\n\n", cycle)
			t.Skip("retention accounting rejects the amplifying payload; attack precondition not met")
		}

		// Chain reaches that view: processBacklog posts every message and zeroes
		// the counters, but the messages stay alive in the handoff goroutines.
		c.current = newRoundState(
			&istanbul.View{Sequence: big.NewInt(next), Round: big.NewInt(0)},
			valSet, nil, nil, nil, nil, func(common.Hash) bool { return false },
		)
		c.state = StateAcceptRequest
		c.processBacklog()

		h := heapNow()
		fmt.Printf("  %-6d %-16.2f %-16.2f %d\n",
			cycle, mib(uint64(charged)), mib(h-base), runtime.NumGoroutine())

		if charged > MaxBacklogBytesPerValidator {
			t.Fatalf("cycle %d exceeded the charged budget (%d) - attack would have been blocked", cycle, charged)
		}
	}

	final := heapNow() - base
	runtime.KeepAlive(c)
	runtime.KeepAlive(wires)

	fmt.Printf("\n  charged budget never exceeded : %.0f MiB\n", mib(MaxBacklogBytesPerValidator))
	fmt.Printf("  resident after %d cycles       : %.2f MiB\n", cycles, mib(final))
	fmt.Printf("  growth is linear in cycles -> unbounded\n\n")

	if final > uint64(MaxBacklogBytesTotalCeiling) {
		t.Errorf("UNBOUNDED: %.2f MiB resident from a single sender; the global ceiling is %.0f MiB "+
			"and the per-sender budget is %.0f MiB",
			mib(final), mib(MaxBacklogBytesTotalCeiling), mib(MaxBacklogBytesPerValidator))
	}
}
