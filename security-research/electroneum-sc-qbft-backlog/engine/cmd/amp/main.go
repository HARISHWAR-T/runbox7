package main

// Phase 1 of the payload engine: measure the amplification factor between the
// encoded wire size the backlog byte budget charges, and the decoded heap the
// node actually retains.

import (
	"fmt"
	"runtime"
	"runtime/debug"

	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/hunt"
)

func heapAlloc() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// measure decodes n copies of payload, holds them all live, and reports the
// retained heap delta.
func measure(payload []byte, n int) (retained uint64, err error) {
	// Pre-allocate the n input copies so their cost is inside the baseline and
	// does not pollute the delta.
	inputs := make([][]byte, n)
	for i := range inputs {
		inputs[i] = append([]byte(nil), payload...)
	}
	held := make([]qbfttypes.QBFTMessage, 0, n)

	base := heapAlloc()
	for i := 0; i < n; i++ {
		m, e := qbfttypes.Decode(qbfttypes.PreprepareCode, inputs[i])
		if e != nil {
			return 0, e
		}
		held = append(held, m)
	}
	after := heapAlloc()

	runtime.KeepAlive(held)
	runtime.KeepAlive(inputs)
	if after < base {
		return 0, fmt.Errorf("negative delta")
	}
	return after - base, nil
}

type result struct {
	g       hunt.Genome
	encoded int
	perMsg  uint64
	amp     float64
}

func score(g hunt.Genome, n int) (result, error) {
	p := g.BuildPreprepare()
	ret, err := measure(p, n)
	if err != nil {
		return result{}, err
	}
	perMsg := ret / uint64(n)
	return result{
		g:       g,
		encoded: len(p),
		perMsg:  perMsg,
		amp:     float64(ret) / float64(uint64(n)*uint64(len(p))),
	}, nil
}

func main() {
	debug.SetGCPercent(20)

	fmt.Println("== unit cost of each primitive (single-element deltas) ==")
	for k := hunt.TxKind(0); k < 4; k++ {
		lo := hunt.Genome{Kind: k, NTx: 1000}
		hi := hunt.Genome{Kind: k, NTx: 21000}
		rl, err := score(lo, 8)
		if err != nil {
			fmt.Println("  err:", err)
			continue
		}
		rh, err := score(hi, 8)
		if err != nil {
			fmt.Println("  err:", err)
			continue
		}
		dBytes := rh.encoded - rl.encoded
		dHeap := int64(rh.perMsg) - int64(rl.perMsg)
		fmt.Printf("  %-16s marginal: %d encoded bytes -> %d heap bytes  (x%.1f)\n",
			k, dBytes/20000, dHeap/20000, float64(dHeap)/float64(dBytes))
	}

	fmt.Println("\n== whole-message amplification, sized near the 4 MiB per-message ceiling ==")
	const ceiling = 4 * 1024 * 1024
	best := result{}
	for k := hunt.TxKind(0); k < 4; k++ {
		// binary search the tx count that lands just under the ceiling
		lo, hi := 0, 2_000_000
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if len(hunt.Genome{Kind: k, NTx: mid}.BuildPreprepare()) <= ceiling {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		r, err := score(hunt.Genome{Kind: k, NTx: lo}, 4)
		if err != nil {
			fmt.Println("  err:", err)
			continue
		}
		fmt.Printf("  %-16s ntx=%-8d encoded=%.2f MiB  retained=%.2f MiB  amplification=x%.1f\n",
			k, lo, float64(r.encoded)/1048576, float64(r.perMsg)/1048576, r.amp)
		if r.amp > best.amp {
			best = r
		}
	}

	fmt.Printf("\n== BEST: %s  x%.1f ==\n", best.g, best.amp)
	fmt.Printf("Per-validator budget  %4d MiB encoded -> %8.1f MiB retained\n",
		32, 32*best.amp)
	fmt.Printf("Global budget (floor) %4d MiB encoded -> %8.1f MiB retained\n",
		128, 128*best.amp)
	fmt.Printf("Global budget (ceil)  %4d MiB encoded -> %8.1f MiB retained\n",
		512, 512*best.amp)
}
