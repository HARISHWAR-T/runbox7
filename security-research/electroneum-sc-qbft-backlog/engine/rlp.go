package hunt

// Minimal hand-rolled RLP writer. We need byte-exact control over the wire
// encoding so the payload engine can emit the *smallest legal* encoding of a
// structure that the decoder will still materialise in full.

func encodeLen(l int, offset byte) []byte {
	if l < 56 {
		return []byte{offset + byte(l)}
	}
	// big-endian length-of-length
	var b []byte
	for n := l; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	return append([]byte{offset + 55 + byte(len(b))}, b...)
}

// Str encodes a byte string.
func Str(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(encodeLen(len(b), 0x80), b...)
}

// List encodes a list from already-encoded items.
func List(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return append(encodeLen(len(body), 0xc0), body...)
}

// Cat concatenates already-encoded items without adding a list header.
func Cat(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return body
}

// Empty is the canonical zero/empty value: 0x80. Decodes to 0, nil, or "".
var Empty = []byte{0x80}

// EmptyList is the empty list: 0xc0.
var EmptyList = []byte{0xc0}

// Rep returns n copies of item concatenated.
func Rep(item []byte, n int) []byte {
	out := make([]byte, 0, len(item)*n)
	for i := 0; i < n; i++ {
		out = append(out, item...)
	}
	return out
}

// Bytes of fixed length, zero-filled (for fixed-size fields like hashes).
func Zeros(n int) []byte { return Str(make([]byte, n)) }
