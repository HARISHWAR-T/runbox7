package hunt

// Payload engine for QBFT PRE-PREPARE / ROUND-CHANGE wire messages.
//
// The backlog admission control in consensus/istanbul/core/backlog.go charges a
// byte budget against len(data) -- the *encoded wire size*. What it actually
// retains is the *decoded* object graph. This engine generates messages that
// maximise decoded-heap-per-encoded-byte, i.e. the amplification factor between
// what the budget measures and what the node pays.

import "fmt"

// TxKind selects which transaction encoding the engine emits inside the block.
type TxKind int

const (
	TxLegacyMin     TxKind = iota // [n,gp,g,to,v,d,V,R,S] all empty  -> 10 bytes
	TxPriorityMin                 // typed 0x40, 15 fields all empty
	TxDynFeeMin                   // typed 0x02, 12 fields all empty
	TxAccessListMin               // typed 0x01, 11 fields all empty
	txKindCount
)

func (k TxKind) String() string {
	switch k {
	case TxLegacyMin:
		return "legacy-min"
	case TxPriorityMin:
		return "priority-min"
	case TxDynFeeMin:
		return "dynfee-min"
	case TxAccessListMin:
		return "accesslist-min"
	}
	return "?"
}

// txEncoding returns the smallest legal wire encoding of a transaction of the
// given kind, as it appears as an element of the block's Txs list.
func txEncoding(k TxKind) []byte {
	switch k {
	case TxLegacyMin:
		// LegacyTx: Nonce, GasPrice, Gas, To, Value, Data, V, R, S
		return List(Rep(Empty, 9))
	case TxPriorityMin:
		// PriorityTx: ChainID, Nonce, GasTipCap, GasFeeCap, Gas, To, Value,
		// Data, AccessList, V, R, S, PriorityV, PriorityR, PriorityS
		inner := List(Cat(Rep(Empty, 8), EmptyList, Rep(Empty, 6)))
		return Str(append([]byte{0x40}, inner...))
	case TxDynFeeMin:
		// DynamicFeeTx: ChainID, Nonce, GasTipCap, GasFeeCap, Gas, To, Value,
		// Data, AccessList, V, R, S
		inner := List(Cat(Rep(Empty, 8), EmptyList, Rep(Empty, 3)))
		return Str(append([]byte{0x02}, inner...))
	case TxAccessListMin:
		// AccessListTx: ChainID, Nonce, GasPrice, Gas, To, Value, Data,
		// AccessList, V, R, S
		inner := List(Cat(Rep(Empty, 7), EmptyList, Rep(Empty, 3)))
		return Str(append([]byte{0x01}, inner...))
	}
	panic("bad kind")
}

// minHeader is the smallest legal *types.Header encoding. The fixed-size hash
// and bloom fields dominate it, so headers are a poor amplifier -- we emit
// exactly one, for the block, and let the engine decide about uncles.
func minHeader() []byte {
	return List(
		Zeros(32),  // ParentHash
		Zeros(32),  // UncleHash
		Zeros(20),  // Coinbase
		Zeros(32),  // Root
		Zeros(32),  // TxHash
		Zeros(32),  // ReceiptHash
		Zeros(256), // Bloom
		Empty,      // Difficulty
		Empty,      // Number
		Empty,      // GasLimit
		Empty,      // GasUsed
		Empty,      // Time
		Empty,      // Extra
		Zeros(32),  // MixDigest
		Zeros(8),   // Nonce
	)
}

// minPrepare is the smallest legal *Prepare: [[Seq,Round,Digest],Sig]
func minPrepare() []byte {
	return List(List(Empty, Empty, Zeros(32)), Empty)
}

// Genome parameterises one generated payload.
type Genome struct {
	Kind     TxKind
	NTx      int
	NUncles  int
	NPrepare int
	Seq      uint64
	Round    uint64
}

func u64(v uint64) []byte {
	if v == 0 {
		return Empty
	}
	var b []byte
	for n := v; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	return Str(b)
}

// PreprepareCode is the QBFT message code for PRE-PREPARE. Duplicated here so
// the engine stays free of a consensus-package import.
const PreprepareCode = 0x12

// block renders the embedded *types.Block: [Header, Txs, Uncles].
func (g Genome) block() []byte {
	return List(
		minHeader(),
		List(Rep(txEncoding(g.Kind), g.NTx)),
		List(Rep(minHeader(), g.NUncles)),
	)
}

// signedPayload is the inner [Sequence, Round, Proposal] tuple.
func (g Genome) signedPayload() []byte {
	return List(u64(g.Seq), u64(g.Round), g.block())
}

// SigningPayload reproduces Preprepare.EncodePayloadForSigning byte-for-byte:
//
//	rlp([ Code, [Sequence, Round, Proposal] ])
//
// Keccak256 of this is what a validator signs, and what verifySignatures
// ecrecovers against. Building it here (rather than encoding a decoded message)
// keeps the engine on the wire side of the boundary throughout.
func (g Genome) SigningPayload() []byte {
	return List(Str([]byte{PreprepareCode}), g.signedPayload())
}

// BuildSigned renders the genome as a full PRE-PREPARE wire payload carrying the
// supplied 65-byte signature:
//
//	[ [ [Seq, Round, Block], Sig ], [ [RoundChanges], [Prepares] ] ]
func (g Genome) BuildSigned(sig []byte) []byte {
	signed := List(g.signedPayload(), Str(sig))
	just := List(EmptyList, List(Rep(minPrepare(), g.NPrepare)))
	return List(signed, just)
}

// BuildPreprepare renders the genome with a zeroed placeholder signature. Use
// BuildSigned when the message must survive verifySignatures.
func (g Genome) BuildPreprepare() []byte {
	return g.BuildSigned(make([]byte, 65))
}

func (g Genome) String() string {
	return fmt.Sprintf("{kind=%s ntx=%d nuncle=%d nprep=%d}", g.Kind, g.NTx, g.NUncles, g.NPrepare)
}
