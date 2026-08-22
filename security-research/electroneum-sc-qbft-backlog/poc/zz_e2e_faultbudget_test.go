package core

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
)

// TestE2E_WithinByzantineFaultBudget scales the attack to the number of faulty
// validators QBFT is explicitly designed to tolerate.
//
// QBFT tolerates f = (N-1)/3 Byzantine validators. Each of them can fill its own
// 32 MiB per-sender budget with signed, amplifying PRE-PREPAREs, and f * 32 MiB
// stays well under the global byte budget, so every message is admitted. The
// resident cost is f * ~1.2 GiB.
//
// This is the severity argument: the memory a correct node is forced to hold is
// set by the fault budget the protocol already promises to survive.
func TestE2E_WithinByzantineFaultBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates several GiB")
	}

	const n = 13 // f = (13-1)/3 = 4
	valSet, keys := newKeyedValidatorSet(t, n)
	f := (n - 1) / 3

	c := newTestCore(valSet, 1, 0)
	c.validateFn = c.checkValidatorSignature
	c.address = valSet.List()[0].Address()

	const msgSize = MaxFuturePreprepareBytes
	perSender := MaxBacklogBytesPerValidator / msgSize

	// Validators 1..f are Byzantine; validator 0 is the node under attack.
	attackers := make([]common.Address, 0, f)
	for i := 1; i <= f; i++ {
		attackers = append(attackers, valSet.List()[i].Address())
	}

	type frame struct {
		bytes []byte
	}
	frames := make([]frame, 0, f*perSender)
	for _, a := range attackers {
		for i := 0; i < perSender; i++ {
			g := fitGenome(uint64(2+i), msgSize)
			frames = append(frames, frame{bytes: signedWire(t, g, keys[a])})
		}
	}

	globalBudget := c.maxBacklogBytesTotal()

	base := heapNow()
	for _, fr := range frames {
		if err := c.handleEncodedMsg(0x12, fr.bytes); err != nil && err != errFutureMessage {
			t.Fatalf("frame rejected: %v", err)
		}
	}
	after := heapNow()
	runtime.KeepAlive(frames)

	if c.backlogsTotal != len(frames) {
		fmt.Printf("\n[MITIGATED] only %d/%d frames retained; resident=%.2f MiB\n\n",
			c.backlogsTotal, len(frames), mib(after-base))
		t.Skip("retention accounting rejects the amplifying payload; attack precondition not met")
	}

	charged := uint64(c.backlogsBytesTotal)
	resident := after - base

	fmt.Printf("\n=== E2E: SCALED TO THE BYZANTINE FAULT BUDGET ===\n")
	fmt.Printf("  validator set        : N=%d, tolerated faults f=%d\n", n, f)
	fmt.Printf("  Byzantine validators : %d (exactly f — the protocol promises to survive this)\n", f)
	fmt.Printf("  frames admitted      : %d, all signature-verified\n", c.backlogsTotal)
	fmt.Printf("  global byte budget   : %8.2f MiB\n", mib(uint64(globalBudget)))
	fmt.Printf("  charged              : %8.2f MiB  (%.0f%% of the global budget)\n",
		mib(charged), 100*float64(charged)/float64(globalBudget))
	fmt.Printf("  resident             : %8.2f MiB\n", mib(resident))
	fmt.Printf("  amplification        : x%.1f\n\n", float64(resident)/float64(charged))

	if resident > uint64(globalBudget) {
		t.Errorf("FAULT-BUDGET BYPASS: %d Byzantine validators (= f) force %.2f MiB resident "+
			"while the global budget reports %.2f MiB of %.0f MiB used",
			f, mib(resident), mib(charged), mib(uint64(globalBudget)))
	}
}
