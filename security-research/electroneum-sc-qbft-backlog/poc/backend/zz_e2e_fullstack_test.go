package backend

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/hunt"
	"github.com/electroneum/electroneum-sc/p2p"
)

// Mirrors the constants in consensus/istanbul/core (unexported there).
const (
	e2eMaxFuturePreprepareBytes    = 4 * 1024 * 1024
	e2eMaxBacklogBytesPerValidator = 32 * 1024 * 1024
)

func e2eHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func e2eMiB(b uint64) float64 { return float64(b) / (1024 * 1024) }

func e2eFit(seq uint64, limit int) hunt.Genome {
	lo, hi := 0, 2_000_000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len((hunt.Genome{Kind: hunt.TxLegacyMin, NTx: mid, Seq: seq}).BuildPreprepare()) <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return hunt.Genome{Kind: hunt.TxLegacyMin, NTx: lo, Seq: seq}
}

func e2eSign(t *testing.T, g hunt.Genome, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	sig, err := crypto.Sign(crypto.Keccak256(g.SigningPayload()), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return g.BuildSigned(sig)
}

// TestE2E_FullStack_HandleMsgAmplification is the complete attack, delivered the
// way a real peer delivers it.
//
// A real Backend is stood up on a real BlockChain with a real 4-validator set and
// a live QBFT core (Backend.Start -> startQBFT -> core.Start -> handleEvents).
// The attacker holds ONE validator private key and sends ordinary p2p frames.
// Nothing in the node is stubbed, patched, or reached into: the only entry point
// used is Backend.HandleMsg, which is what the eth protocol handler calls for a
// consensus frame from any connected peer.
//
// Full production path exercised:
//
//	Backend.HandleMsg -> istanbulEventMux.Post -> core.handleEvents
//	  -> handleEncodedMsg -> qbfttypes.Decode -> verifySignatures
//	  -> checkMessage (future) -> addToBacklog (all admission checks)
func TestE2E_FullStack_HandleMsgAmplification(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates >1 GiB")
	}

	genesis, nodeKeys := testutils.GenesisAndKeys(4)
	chain, be := newBlockchainFromConfig(genesis, nodeKeys, copyConfig(istanbul.DefaultConfig))
	defer be.Stop()
	defer chain.Stop()

	// The attacker is any validator other than the node under attack.
	// addToBacklog drops messages whose recovered source is the node itself.
	var attackerKey *ecdsa.PrivateKey
	var attacker common.Address
	for _, k := range nodeKeys {
		if a := crypto.PubkeyToAddress(k.PublicKey); a != be.Address() {
			attackerKey, attacker = k, a
			break
		}
	}
	if attackerKey == nil {
		t.Fatal("no validator key available other than the node's own")
	}

	// Chain head is genesis, so the node's current sequence is 1. Sequences 2..9
	// are inside the 32-block future window addToBacklog allows.
	const msgSize = e2eMaxFuturePreprepareBytes
	nFrames := e2eMaxBacklogBytesPerValidator / msgSize

	frames := make([][]byte, 0, nFrames)
	for i := 0; i < nFrames; i++ {
		frames = append(frames, e2eSign(t, e2eFit(uint64(2+i), msgSize), attackerKey))
	}

	wire := 0
	for _, f := range frames {
		wire += len(f)
	}

	base := e2eHeap()
	for _, f := range frames {
		handled, err := be.HandleMsg(attacker, p2p.Msg{
			Code:    qbfttypes.PreprepareCode,
			Size:    uint32(len(f)),
			Payload: bytes.NewReader(f),
		})
		if !handled {
			t.Fatalf("HandleMsg did not accept a consensus frame (err=%v)", err)
		}
	}

	// HandleMsg returns once the mux consumer accepts the event; give the core
	// goroutine time to finish decoding and admitting the last frames.
	settle := e2eHeap()
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		cur := e2eHeap()
		if cur <= settle+(1<<20) && cur >= settle-(1<<20) {
			break
		}
		settle = cur
	}
	after := e2eHeap()
	runtime.KeepAlive(frames)

	resident := after - base

	fmt.Printf("\n=== E2E FULL STACK: p2p frame -> live QBFT node ===\n")
	fmt.Printf("  node under attack : %s (validator set of 4)\n", be.Address().Hex()[:12])
	fmt.Printf("  attacker          : %s (holds 1 validator key)\n", attacker.Hex()[:12])
	fmt.Printf("  frames delivered  : %d via Backend.HandleMsg\n", nFrames)
	fmt.Printf("  bytes on the wire : %8.2f MiB   (per-sender budget %.0f MiB)\n",
		e2eMiB(uint64(wire)), e2eMiB(e2eMaxBacklogBytesPerValidator))
	fmt.Printf("  heap resident     : %8.2f MiB\n", e2eMiB(resident))
	fmt.Printf("  amplification     : x%.1f\n\n", float64(resident)/float64(wire))

	if resident < uint64(e2eMaxBacklogBytesPerValidator) {
		fmt.Printf("[MITIGATED] resident %.2f MiB stays within the %.0f MiB per-sender budget\n\n",
			e2eMiB(resident), e2eMiB(e2eMaxBacklogBytesPerValidator))
		return
	}
	if resident > uint64(e2eMaxBacklogBytesPerValidator) {
		t.Errorf("E2E FULL-STACK BYPASS: %.2f MiB resident on a live node from %.2f MiB of wire traffic "+
			"sent by one validator whose backlog budget is %.0f MiB",
			e2eMiB(resident), e2eMiB(uint64(wire)), e2eMiB(e2eMaxBacklogBytesPerValidator))
	}
}
