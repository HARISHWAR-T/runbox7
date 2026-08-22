package backend

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/p2p"
)

// TestUnauth_MultiPeerCrossesRoundTimeout scales the stall by connecting more
// unauthenticated peers. The node under attack is a validator; whether it is the
// round's proposer varies per run and is printed, not assumed.
//
// Backend.HandleMsg holds sb.coreMu for its whole body and posts synchronously,
// so every peer's consensus frame serialises through one critical section. Go's
// mutex switches to FIFO handoff after ~1ms of contention, which is why a single
// attacking peer produces a plateau rather than unbounded delay: the honest sender only
// waits behind roughly one frame.
//
// Adding peers adds queue positions. A legitimate validator's frame waits behind
// one in-flight decode per attacking peer, so the delay scales with peer count --
// and peers cost nothing, since no key is needed.
//
// The thresholds that matter are the protocol's own: BlockPeriod (5s) is the
// target block interval, and RequestTimeoutSeconds (10s) is the QBFT round
// timeout. Crossing the latter makes the node give up on the round and broadcast
// a ROUND-CHANGE.
func TestUnauth_MultiPeerCrossesRoundTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates >1 GiB")
	}

	genesis, nodeKeys := testutils.GenesisAndKeys(4)
	chain, be := newBlockchainFromConfig(genesis, nodeKeys, copyConfig(istanbul.DefaultConfig))
	defer be.Stop()
	defer chain.Stop()

	cfg := istanbul.DefaultConfig
	blockPeriod := time.Duration(cfg.BlockPeriod) * time.Second
	roundTimeout := time.Duration(cfg.RequestTimeoutSeconds) * time.Second

	// honestValidator is the SENDER of the legitimate frame we time -- a real
	// member of the validator set. The node under attack is `be`.
	//
	// Note on roles: the validator set is generated from fresh random keys each
	// run, and newBlockchainFromConfig builds the backend from nodeKeys[0], so
	// whether `be` happens to be the genesis proposer varies run to run. The run
	// prints IsProposer() so the role is stated rather than assumed; both values
	// have been observed crossing the round timeout. The attack does not depend on
	// the target's role -- it stalls that node's consensus ingress, and every
	// validator has to PREPARE and COMMIT for a round to close.
	honestValidator := crypto.PubkeyToAddress(nodeKeys[1].PublicKey)

	send := func(from common.Address, f []byte) time.Duration {
		start := time.Now()
		be.HandleMsg(from, p2p.Msg{
			Code:    qbfttypes.PreprepareCode,
			Size:    uint32(len(f)),
			Payload: bytes.NewReader(f),
		})
		return time.Since(start)
	}

	bigTx := fitTx(transportFrameCap)
	smallTx := fitTx(4096)

	var baseline time.Duration
	for i := 0; i < 5; i++ {
		if d := send(honestValidator, frameWith(smallTx, uint64(80+i))); d > baseline {
			baseline = d
		}
	}

	fmt.Printf("\n=== UNAUTHENTICATED PEERS vs THE QBFT ROUND TIMEOUT ===\n")
	fmt.Printf("  node under attack : %s (4-validator set, IsProposer=%v)\n",
		be.Address().Hex()[:12], be.core.IsProposer())
	fmt.Printf("  honest sender     : %s (real validator)\n", honestValidator.Hex()[:12])
	fmt.Printf("  BlockPeriod       : %s   (target block interval)\n", blockPeriod)
	fmt.Printf("  RequestTimeout    : %s  (QBFT round timeout)\n", roundTimeout)
	fmt.Printf("  legit frame, idle : %s\n\n", baseline.Round(time.Microsecond))
	fmt.Printf("  %-8s %-14s %-14s %s\n", "peers", "legit frame", "vs BlockPeriod", "vs RequestTimeout")

	seq := uint64(20000)
	const framesPerPeer = 3
	crossed := false

	for _, peers := range []int{1, 2, 4, 8} {
		// Distinct non-validator identities: one enode key each, no validator
		// material of any kind.
		frames := make([][][]byte, peers)
		for p := 0; p < peers; p++ {
			frames[p] = make([][]byte, framesPerPeer)
			for i := 0; i < framesPerPeer; i++ {
				seq++
				frames[p][i] = frameWith(bigTx, seq)
			}
		}

		var wg sync.WaitGroup
		stop := make(chan struct{})
		for p := 0; p < peers; p++ {
			key, _ := crypto.GenerateKey()
			addr := crypto.PubkeyToAddress(key.PublicKey)
			wg.Add(1)
			go func(p int, addr common.Address) {
				defer wg.Done()
				for _, f := range frames[p] {
					select {
					case <-stop:
						return
					default:
					}
					send(addr, f)
				}
			}(p, addr)
		}

		// Let every peer get a frame in flight before timing the honest frame.
		time.Sleep(400 * time.Millisecond)
		seq++
		stalled := send(honestValidator, frameWith(smallTx, seq))
		close(stop)
		wg.Wait()

		bp, rt := "-", "-"
		if stalled > blockPeriod {
			bp = "EXCEEDED"
		}
		if stalled > roundTimeout {
			rt = "EXCEEDED"
			crossed = true
		}
		fmt.Printf("  %-8d %-14s %-14s %s\n", peers, stalled.Round(time.Millisecond), bp, rt)
	}

	fmt.Printf("\n  Peers cost nothing: no validator key, no stake, no allowlist entry.\n")
	if crossed {
		fmt.Printf("  ROUND TIMEOUT CROSSED: the honest frame arrives after the round timer has\n")
		fmt.Printf("  already expired. This test measures the delay only -- it does NOT observe a\n")
		fmt.Printf("  round failing to close. An isolated node fires its round-change timer with or\n")
		fmt.Printf("  without an attacker, so a ROUND-CHANGE seen here would prove nothing; showing\n")
		fmt.Printf("  that needs a multi-node devnet where rounds otherwise complete.\n\n")
	} else {
		fmt.Printf("  Round timeout NOT crossed on this host at these peer counts.\n\n")
	}
}
