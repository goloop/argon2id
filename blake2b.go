package argon2id

// BLAKE2b (RFC 7693), the hash Argon2 is built on. The standard library does
// not ship it, so this is a compact, self-contained, stdlib-only one-shot
// implementation: no keying, no streaming, no tree mode - only what Argon2id
// needs (a digest of a byte slice at a chosen length, and the variable-length
// H' construction). It is validated against the RFC 7693 "abc" vector and,
// transitively, the RFC 9106 Argon2id vector in the tests.

import (
	"encoding/binary"
	"math/bits"
)

// blake2bIV is the BLAKE2b initialization vector (the fractional parts of the
// square roots of the first eight primes), identical to SHA-512's.
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// blake2bSigma is the message word schedule for the twelve rounds.
var blake2bSigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// blake2bG is the BLAKE2b mixing function G, working in place on the working
// vector v.
func blake2bG(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] = v[a] + v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] = v[a] + v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}

// blake2bCompress mixes one 128-byte block into the state h. t0/t1 are the
// low/high 64 bits of the byte counter; last marks the final block.
func blake2bCompress(h *[8]uint64, block []byte, t0, t1 uint64, last bool) {
	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= t0
	v[13] ^= t1
	if last {
		v[14] = ^v[14]
	}

	for r := 0; r < 12; r++ {
		s := &blake2bSigma[r]
		blake2bG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2bG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2bG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2bG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2bG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2bG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2bG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2bG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// blake2bSum writes the BLAKE2b digest of in into out; len(out) (1..64) is the
// digest length. Unkeyed, sequential mode.
func blake2bSum(out, in []byte) {
	outLen := len(out)

	var h [8]uint64
	copy(h[:], blake2bIV[:])
	// Parameter block, sequential unkeyed: digest length, key length 0,
	// fanout 1, depth 1.
	h[0] ^= 0x0000000001010000 ^ uint64(outLen)

	// Compress every full block except the final one, which is always run with
	// the last-block flag (even when the message is empty or block-aligned).
	var t0 uint64
	i := 0
	for len(in)-i > 128 {
		t0 += 128
		blake2bCompress(&h, in[i:i+128], t0, 0, false)
		i += 128
	}
	var final [128]byte
	rem := copy(final[:], in[i:])
	t0 += uint64(rem)
	blake2bCompress(&h, final[:], t0, 0, true)

	var digest [64]byte
	for j := 0; j < 8; j++ {
		binary.LittleEndian.PutUint64(digest[j*8:], h[j])
	}
	copy(out, digest[:outLen])
}

// blake2bLong is Argon2's variable-length hash H': for an output up to 64 bytes
// it is a single BLAKE2b of LE32(len)||in; for longer outputs it emits 32-byte
// blocks from a chain of BLAKE2b-512 hashes, with a final block sized to fill
// the remainder (RFC 9106 section 3.3).
func blake2bLong(out, in []byte) {
	outLen := len(out)

	pre := make([]byte, 4+len(in))
	binary.LittleEndian.PutUint32(pre, uint32(outLen))
	copy(pre[4:], in)

	if outLen <= 64 {
		blake2bSum(out, pre)
		return
	}

	var v [64]byte
	blake2bSum(v[:], pre)
	copy(out, v[:32])
	pos := 32
	for outLen-pos > 64 {
		blake2bSum(v[:], v[:])
		copy(out[pos:], v[:32])
		pos += 32
	}
	blake2bSum(out[pos:], v[:])
}
