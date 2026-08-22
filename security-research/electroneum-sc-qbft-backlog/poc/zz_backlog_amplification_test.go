package core

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/hunt"
)

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func mib(b uint64) float64 { return float64(b) / (1024 * 1024) }

// buildWire renders a PRE-PREPARE *wire payload* of ~targetBytes whose block
// body is packed with minimally-encoded legacy transactions. It deliberately
// stops at the bytes: decoding must happen inside the measured window, because
// the decoded graph is exactly what we are trying to weigh.
func buildWire(seq uint64, targetBytes int) []byte {
	lo, hi := 0, 2_000_000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len(hunt.Genome{Kind: hunt.TxLegacyMin, NTx: mid, Seq: seq}.BuildPreprepare()) <= targetBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return hunt.Genome{Kind: hunt.TxLegacyMin, NTx: lo, Seq: seq}.BuildPreprepare()
}

// admit decodes a wire payload exactly as handleEncodedMsg does and feeds it to
// the real addToBacklog with the same encodedSize the production path charges.
func admit(t *testing.T, c *core, wire []byte, src common.Address) {
	t.Helper()
	msg, err := qbfttypes.Decode(qbfttypes.PreprepareCode, wire)
	if err != nil {
		t.Fatalf("engine produced an undecodable payload: %v", err)
	}
	msg.SetSource(src)
	c.addToBacklog(msg, len(wire))
}

// TestBacklogByteBudget_AmplificationBypass drives the real addToBacklog
// admission control with engine-generated payloads and compares the bytes the
// budget believes it is retaining against the heap actually retained.
//
// The budget is charged len(data) -- the encoded wire size. What is retained is
// the decoded object graph. For a block packed with minimally-encoded
// transactions those two quantities differ by more than an order of magnitude,
// so "aggregate memory is actually bounded" does not hold.
func TestBacklogByteBudget_AmplificationBypass(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)
	src := valSet.List()[1].Address()

	// One Byzantine validator, filling only its own per-validator budget.
	// Every message is sized just under the per-message ceiling, so every
	// admission check in addToBacklog passes.
	const msgSize = MaxFuturePreprepareBytes // 4 MiB, the documented ceiling
	nMsgs := MaxBacklogBytesPerValidator / msgSize

	// Build all wire payloads up front so their cost sits inside the baseline.
	wires := make([][]byte, 0, nMsgs)
	for i := 0; i < nMsgs; i++ {
		wires = append(wires, buildWire(uint64(2+i), msgSize))
	}

	base := heapNow()
	for _, w := range wires {
		admit(t, c, w, src)
	}
	after := heapNow()
	runtime.KeepAlive(wires)

	if c.backlogsTotal != nMsgs {
		fmt.Printf("\n[MITIGATED] only %d/%d amplifying payloads admitted; retained=%.2f MiB\n\n",
			c.backlogsTotal, nMsgs, mib(after-base))
		if after-base > uint64(MaxBacklogBytesPerValidator) {
			t.Errorf("still over budget: %.2f MiB resident", mib(after-base))
		}
		return
	}

	charged := uint64(c.backlogsBytesTotal)
	retained := after - base

	fmt.Printf("\n=== BACKLOG BYTE BUDGET vs ACTUAL RETAINED HEAP ===\n")
	fmt.Printf("  messages admitted        : %d (each %.2f MiB encoded, at the per-message ceiling)\n",
		c.backlogsTotal, mib(uint64(msgSize)))
	fmt.Printf("  budget believes retained : %8.2f MiB  (cap for this sender: %.0f MiB)\n",
		mib(charged), mib(MaxBacklogBytesPerValidator))
	fmt.Printf("  actually retained on heap: %8.2f MiB\n", mib(retained))
	fmt.Printf("  amplification            : x%.1f\n", float64(retained)/float64(charged))
	fmt.Printf("  ^ from ONE validator, entirely within its per-sender budget\n\n")

	if retained > uint64(MaxBacklogBytesPerValidator) {
		t.Errorf("BUDGET BYPASSED: per-validator budget is %.0f MiB but %.2f MiB is resident (x%.1f)",
			mib(MaxBacklogBytesPerValidator), mib(retained), float64(retained)/float64(charged))
	}
}

// TestBacklogByteBudget_GlobalCeilingBypass projects the measured amplification
// onto the global budget, which is the value the design states is "kept
// comfortably below any validator's RAM".
func TestBacklogByteBudget_GlobalCeilingBypass(t *testing.T) {
	valSet := newTestValidatorSet(4)
	c := newTestCore(valSet, 1, 0)

	src := valSet.List()[1].Address()

	// Measure several copies so the per-message figure is not dominated by GC
	// timing noise from earlier tests in the package.
	const copies = 4
	wires := make([][]byte, copies)
	for i := range wires {
		wires[i] = buildWire(uint64(2+i), MaxFuturePreprepareBytes)
	}
	sz := len(wires[0])

	base := heapNow()
	for _, w := range wires {
		admit(t, c, w, src)
	}
	after := heapNow()
	runtime.KeepAlive(wires)
	runtime.KeepAlive(c) // the backlog IS the retained graph; keep it reachable

	if c.backlogsTotal != copies {
		fmt.Printf("\n[MITIGATED] only %d/%d amplifying payloads admitted\n\n", c.backlogsTotal, copies)
		return
	}
	if after <= base {
		t.Skipf("heap measurement was disturbed by GC (base=%d after=%d); rerun in isolation", base, after)
	}
	perMsg := (after - base) / copies
	amp := float64(perMsg) / float64(sz)

	globalFloor := uint64(MinBacklogBytesTotal)
	globalCeil := uint64(MaxBacklogBytesTotalCeiling)

	fmt.Printf("=== GLOBAL BUDGET PROJECTION (measured x%.1f) ===\n", amp)
	fmt.Printf("  single %.0f MiB message retains        : %8.2f MiB\n", mib(uint64(sz)), mib(perMsg))
	fmt.Printf("  global floor  %4.0f MiB charged retains : %8.2f MiB\n", mib(globalFloor), mib(globalFloor)*amp)
	fmt.Printf("  global ceiling %3.0f MiB charged retains : %8.2f MiB\n", mib(globalCeil), mib(globalCeil)*amp)
	fmt.Printf("  MaxBacklogBytesTotalCeiling is documented as \"comfortably below any validator's RAM\"\n\n")

	if mib(globalCeil)*amp > mib(globalCeil) {
		t.Errorf("GLOBAL BUDGET BYPASSED: ceiling %.0f MiB admits %.0f MiB of resident heap",
			mib(globalCeil), mib(globalCeil)*amp)
	}
}
