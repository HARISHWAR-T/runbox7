package backend

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/hunt"
)

// TestUnauth_RoundChangeAmplifiesToo confirms the same pre-auth decode cost via
// ROUND-CHANGE, which embeds a PreparedBlock. carriesBlockProposal() in
// backlog.go already acknowledges both codes carry a block; the decode that
// materialises it still runs before any signature check for both.
func TestUnauth_RoundChangeAmplifiesToo(t *testing.T) {
	ntx := fitTx(transportFrameCap)
	sig := make([]byte, 65)
	sig[64] = 0x01
	frame := (hunt.Genome{Kind: hunt.TxLegacyMin, NTx: ntx, Seq: 2, Round: 7}).BuildRoundChangeSigned(sig)

	runtime.GC()
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	start := time.Now()
	msg, err := qbfttypes.Decode(qbfttypes.RoundChangeCode, frame)
	elapsed := time.Since(start)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(msg)

	alloc := float64(m1.TotalAlloc-m0.TotalAlloc) / (1 << 20)

	// RoundChange.DecodeRLP decodes PreparedBlock in full and only THEN compares
	// PreparedBlock.Hash() against PreparedDigest. A frame whose digest does not
	// match is rejected -- after the entire block has been materialised. So the
	// cost is paid whether or not the message is well-formed.
	fmt.Printf("\n=== ROUND-CHANGE CARRIES THE SAME PAYLOAD ===\n")
	fmt.Printf("  frame        : %.2f MiB ROUND-CHANGE with a PreparedBlock\n", float64(len(frame))/(1<<20))
	fmt.Printf("  decode result: %v\n", err)
	fmt.Printf("  time         : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  allocated    : %.2f MiB before the digest check rejected it\n\n", alloc)

	if err == nil {
		rc := msg.(*qbfttypes.RoundChange)
		var _ *types.Block = rc.PreparedBlock
	}
	if alloc < 100 {
		t.Errorf("ROUND-CHANGE decode allocated only %.2f MiB; amplification claim not supported", alloc)
	}
}
