package backend

import (
	"fmt"
	"testing"
)

// TestGetBaseBlockReward_GenesisUnderflow probes the istanbul_getBaseBlockReward
// RPC with block 0.
//
// api.go:285 only rejects block numbers ABOVE the head, so 0 passes. engine.go:283
// then calls sb.emission(chain, header.Number.Uint64()-1, ...) which underflows to
// 2^64-1 for the genesis header, and engine.go:284-286 panics on the resulting
// error rather than returning it.
func TestGetBaseBlockReward_GenesisUnderflow(t *testing.T) {
	chain, be := newBlockChain(1)
	defer be.Stop()
	defer chain.Stop()

	genesis := chain.Genesis().Header()

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n=== istanbul_getBaseBlockReward(0) PANICS ===\n")
			fmt.Printf("  panic: %v\n", r)
			var zero uint64
			fmt.Printf("  header.Number=0 -> Uint64()-1 underflows to %d\n\n", zero-1)
			return
		}
		fmt.Printf("\n[no panic] genesis reward query returned normally\n\n")
	}()

	reward := be.GetBaseBlockReward(chain, genesis, nil)
	fmt.Printf("\n[no panic] reward at genesis = %v\n\n", reward)
}
