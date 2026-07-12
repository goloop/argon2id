package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// Errors returned by Verify.
var (
	// ErrMismatch is returned when a password does not match its hash.
	ErrMismatch = errors.New("argon2id: password mismatch")

	// ErrInvalidHash is returned when an encoded hash is malformed or its
	// parameters fall outside the accepted bounds.
	ErrInvalidHash = errors.New("argon2id: invalid hash")
)

// Argon2 constants. A block is 1024 bytes (128 uint64 words); a pass is split
// into four synchronization slices.
const (
	argonBlockWords = 128
	argonSyncPoints = 4
	argon2idType    = 2    // the "y" parameter for the id variant
	argon2Version   = 0x13 // 19
)

// Default parameters. 64 MiB of memory, two passes and a single lane: the
// memory cost sits above common minimum guidance, and one lane with two passes
// matches the usual single-thread server profile. Measure on your own hardware
// (see the benchmark) and tune with the options; the cost is recorded in every
// hash, so a hash made under different settings still verifies.
const (
	defaultMemory  = 64 * 1024 // KiB (64 MiB)
	defaultTime    = 2
	defaultThreads = 1
	defaultSaltLen = 16
	defaultKeyLen  = 32
)

// Verification bounds. A stored hash outside these is rejected before any
// memory is allocated: the ceilings stop a hostile hash from forcing a large
// allocation or a long CPU spend, the floors stop a trivially weak one from
// ever verifying. The ceilings are operational, not the algorithm's maxima:
// they sit well above any sane cost while bounding what a single Verify can be
// made to consume.
const (
	maxMemory  = 1 << 20 // KiB (1 GiB)
	maxTime    = 64
	maxThreads = 255
	minSaltLen = 8
	maxSaltLen = 64
	minKeyLen  = 16
	maxKeyLen  = 128
)

// Hasher hashes and verifies passwords with Argon2id.
type Hasher struct {
	memory  uint32 // KiB
	time    uint32 // passes
	threads uint8  // lanes
	saltLen int
	keyLen  int
}

// Option configures New.
type Option func(*Hasher)

// WithMemory sets the memory cost in KiB. Non-positive values are ignored; the
// value is capped at the verification ceiling.
func WithMemory(kib int) Option {
	return func(h *Hasher) {
		if kib <= 0 {
			return
		}
		if kib > maxMemory {
			kib = maxMemory
		}
		h.memory = uint32(kib)
	}
}

// WithTime sets the number of passes over memory. Non-positive values are
// ignored; the value is capped at the verification ceiling.
func WithTime(passes int) Option {
	return func(h *Hasher) {
		if passes <= 0 {
			return
		}
		if passes > maxTime {
			passes = maxTime
		}
		h.time = uint32(passes)
	}
}

// WithThreads sets the number of lanes (parallelism), clamped to 1..255.
func WithThreads(lanes int) Option {
	return func(h *Hasher) {
		if lanes < 1 {
			lanes = 1
		}
		if lanes > maxThreads {
			lanes = maxThreads
		}
		h.threads = uint8(lanes)
	}
}

// WithSaltLength sets the random salt length in bytes, clamped to 8..64.
func WithSaltLength(n int) Option {
	return func(h *Hasher) {
		if n < minSaltLen {
			n = minSaltLen
		}
		if n > maxSaltLen {
			n = maxSaltLen
		}
		h.saltLen = n
	}
}

// WithKeyLength sets the derived digest length in bytes, clamped to 16..128.
func WithKeyLength(n int) Option {
	return func(h *Hasher) {
		if n < minKeyLen {
			n = minKeyLen
		}
		if n > maxKeyLen {
			n = maxKeyLen
		}
		h.keyLen = n
	}
}

// New returns an Argon2id Hasher configured by opts.
func New(opts ...Option) *Hasher {
	h := &Hasher{
		memory:  defaultMemory,
		time:    defaultTime,
		threads: defaultThreads,
		saltLen: defaultSaltLen,
		keyLen:  defaultKeyLen,
	}
	for _, o := range opts {
		o(h)
	}
	// Never encode a memory below Argon2's own floor (8*lanes blocks): otherwise
	// Hash would mint a hash that this hasher's own Verify would reject as out
	// of bounds.
	if floor := argonSyncPoints * 2 * uint32(h.threads); h.memory < floor {
		h.memory = floor
	}
	return h
}

// Hash returns a PHC-encoded Argon2id hash:
// $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<digest>.
func (h *Hasher) Hash(password []byte) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := deriveKey(password, salt, nil, nil, h.time, h.memory, h.threads, uint32(h.keyLen))
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, h.memory, h.time, h.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// Verify checks password against an encoded Argon2id hash in constant time. A
// hash whose parameters fall outside the verification bounds is rejected as
// invalid before any key derivation runs.
func (h *Hasher) Verify(encoded string, password []byte) error {
	p, err := parse(encoded)
	if err != nil {
		return err
	}
	got := deriveKey(password, p.salt, nil, nil, p.time, p.memory, p.threads, uint32(len(p.digest)))
	if subtle.ConstantTimeCompare(got, p.digest) != 1 {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether encoded should be replaced: true for a malformed
// hash, or one whose memory, time, parallelism, salt or key length is below this
// hasher's current settings. Call it after a successful Verify to upgrade stored
// hashes as defaults strengthen over time.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, err := parse(encoded)
	if err != nil {
		return true
	}
	return p.memory < h.memory ||
		p.time < h.time ||
		p.threads < h.threads ||
		len(p.salt) < h.saltLen ||
		len(p.digest) < h.keyLen
}

// params is a decoded, bounds-checked Argon2id hash.
type params struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	digest  []byte
}

// parse decodes an encoded hash and validates every field against the
// verification bounds, so a malformed or deliberately hostile hash is rejected
// before any memory is allocated. Field lengths are checked before base64
// decoding so an oversized field cannot force a large allocation.
func parse(encoded string) (params, error) {
	var p params
	// $argon2id$v=19$m=..,t=..,p=..$salt$digest
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, ErrInvalidHash
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2Version) {
		return p, ErrInvalidHash
	}

	var m, t, threads int
	// Require exactly three fields and reject any trailing garbage by
	// reconstructing the canonical form and comparing.
	if n, _ := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &threads); n != 3 {
		return p, ErrInvalidHash
	}
	if parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", m, t, threads) {
		return p, ErrInvalidHash
	}
	if m <= 0 || m > maxMemory || t <= 0 || t > maxTime ||
		threads < 1 || threads > maxThreads {
		return p, ErrInvalidHash
	}
	if uint32(m) < argonSyncPoints*2*uint32(threads) {
		return p, ErrInvalidHash
	}

	// Bound the encoded field lengths before decoding.
	if len(parts[4]) > base64.RawStdEncoding.EncodedLen(maxSaltLen) ||
		len(parts[5]) > base64.RawStdEncoding.EncodedLen(maxKeyLen) {
		return p, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return p, ErrInvalidHash
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(digest) < minKeyLen || len(digest) > maxKeyLen {
		return p, ErrInvalidHash
	}

	p = params{
		memory:  uint32(m),
		time:    uint32(t),
		threads: uint8(threads),
		salt:    salt,
		digest:  digest,
	}
	return p, nil
}

// argonBlock is a single 1024-byte Argon2 memory block.
type argonBlock [argonBlockWords]uint64

// deriveKey derives a keyLen-byte Argon2id tag. secret and data may be nil;
// they are parameters only so the tests can reproduce the RFC 9106 vector,
// which includes a secret key and associated data.
func deriveKey(password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	laneCount := uint32(threads)

	// Round memory down to a multiple of 4*lanes, with a floor of 8*lanes.
	memBlocks := memory
	if memBlocks < 2*argonSyncPoints*laneCount {
		memBlocks = 2 * argonSyncPoints * laneCount
	}
	memBlocks = (memBlocks / (argonSyncPoints * laneCount)) * (argonSyncPoints * laneCount)
	cols := memBlocks / laneCount // blocks per lane
	segments := cols / argonSyncPoints

	B := make([]argonBlock, memBlocks)

	// H0 and the two seed blocks per lane.
	h0 := initHash(password, salt, secret, data, time, memory, laneCount, keyLen)
	initBlocks(B, h0, laneCount, cols)

	// Fill the memory.
	for pass := uint32(0); pass < time; pass++ {
		for slice := uint32(0); slice < argonSyncPoints; slice++ {
			for lane := uint32(0); lane < laneCount; lane++ {
				fillSegment(B, pass, slice, lane, laneCount, cols, segments, memBlocks, time)
			}
		}
	}

	// Final: XOR the last block of every lane, then H' it to keyLen bytes.
	var c argonBlock
	copy(c[:], B[cols-1][:])
	for lane := uint32(1); lane < laneCount; lane++ {
		last := &B[lane*cols+cols-1]
		for i := range c {
			c[i] ^= last[i]
		}
	}
	var block [1024]byte
	blockToBytes(&block, &c)
	out := make([]byte, keyLen)
	blake2bLong(out, block[:])
	return out
}

// initHash computes H0 (RFC 9106 section 3.2): a BLAKE2b-512 over the
// little-endian parameters followed by the length-prefixed inputs.
func initHash(password, salt, secret, data []byte, time, memory, threads, keyLen uint32) [64]byte {
	buf := make([]byte, 0, 6*4+4*4+len(password)+len(salt)+len(secret)+len(data))
	appendLE32 := func(v uint32) { buf = binary.LittleEndian.AppendUint32(buf, v) }
	appendField := func(b []byte) {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(b)))
		buf = append(buf, b...)
	}
	appendLE32(threads)
	appendLE32(keyLen)
	appendLE32(memory)
	appendLE32(time)
	appendLE32(argon2Version)
	appendLE32(argon2idType)
	appendField(password)
	appendField(salt)
	appendField(secret)
	appendField(data)

	var h0 [64]byte
	blake2bSum(h0[:], buf)
	return h0
}

// initBlocks fills B[lane][0] and B[lane][1] for every lane from H0.
func initBlocks(B []argonBlock, h0 [64]byte, laneCount, cols uint32) {
	var in [72]byte
	copy(in[:64], h0[:])
	var block [1024]byte
	for lane := uint32(0); lane < laneCount; lane++ {
		binary.LittleEndian.PutUint32(in[68:], lane)
		binary.LittleEndian.PutUint32(in[64:], 0)
		blake2bLong(block[:], in[:])
		bytesToBlock(&B[lane*cols+0], block[:])
		binary.LittleEndian.PutUint32(in[64:], 1)
		blake2bLong(block[:], in[:])
		bytesToBlock(&B[lane*cols+1], block[:])
	}
}

// fillSegment fills one segment (one slice of one lane). Argon2id uses
// data-independent addressing for the first two slices of the first pass and
// data-dependent addressing everywhere else.
func fillSegment(B []argonBlock, pass, slice, lane, laneCount, cols, segments, memBlocks, time uint32) {
	dataIndependent := pass == 0 && slice < argonSyncPoints/2

	var addresses, input, zero argonBlock
	if dataIndependent {
		input[0] = uint64(pass)
		input[1] = uint64(lane)
		input[2] = uint64(slice)
		input[3] = uint64(memBlocks)
		input[4] = uint64(time)
		input[5] = uint64(argon2idType)
	}

	index := uint32(0)
	if pass == 0 && slice == 0 {
		index = 2 // the two seed blocks are already filled
		if dataIndependent {
			nextAddresses(&addresses, &input, &zero)
		}
	}

	offset := lane*cols + slice*segments + index
	for ; index < segments; index, offset = index+1, offset+1 {
		prev := offset - 1
		if offset%cols == 0 {
			prev = offset + cols - 1 // wrap to the last block of the lane
		}

		var rnd uint64
		if dataIndependent {
			if index%argonBlockWords == 0 {
				nextAddresses(&addresses, &input, &zero)
			}
			rnd = addresses[index%argonBlockWords]
		} else {
			rnd = B[prev][0]
		}

		refBlock := refIndex(rnd, laneCount, cols, segments, pass, slice, lane, index)
		processBlock(&B[offset], &B[prev], &B[refBlock], true)
	}
}

// nextAddresses regenerates the block of data-independent addresses.
func nextAddresses(addresses, input, zero *argonBlock) {
	input[6]++
	processBlock(addresses, input, zero, false)
	processBlock(addresses, addresses, zero, false)
}

// refIndex maps a pseudo-random value to the absolute index of the reference
// block (RFC 9106 section 3.4).
func refIndex(rnd uint64, laneCount, cols, segments, pass, slice, lane, index uint32) uint32 {
	refLane := uint32(rnd>>32) % laneCount
	if pass == 0 && slice == 0 {
		refLane = lane
	}

	var m, s uint32
	if pass == 0 {
		m = slice * segments
		if slice == 0 || lane == refLane {
			m += index
		}
	} else {
		m = 3 * segments
		s = ((slice + 1) % argonSyncPoints) * segments
		if lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}

	// Relative position within the reference area, biased toward recent blocks.
	x := rnd & 0xffffffff
	x = (x * x) >> 32
	x = (x * uint64(m)) >> 32
	relPos := uint64(s) + uint64(m) - 1 - x
	return refLane*cols + uint32(relPos%uint64(cols))
}

// processBlock is the Argon2 compression function G over two blocks: R = X^Y,
// apply the BlaMka permutation P rowwise then columnwise, and write (or XOR)
// R^permuted into out.
func processBlock(out, x, y *argonBlock, xor bool) {
	var t argonBlock
	for i := range t {
		t[i] = x[i] ^ y[i]
	}

	// Rowwise: eight independent rows of sixteen words.
	for i := 0; i < argonBlockWords; i += 16 {
		blamkaRound(
			&t[i], &t[i+1], &t[i+2], &t[i+3],
			&t[i+4], &t[i+5], &t[i+6], &t[i+7],
			&t[i+8], &t[i+9], &t[i+10], &t[i+11],
			&t[i+12], &t[i+13], &t[i+14], &t[i+15],
		)
	}
	// Columnwise: eight columns, each a pair of words per row.
	for i := 0; i < 16; i += 2 {
		blamkaRound(
			&t[i], &t[i+1], &t[16+i], &t[16+i+1],
			&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
			&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
			&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
		)
	}

	if xor {
		for i := range t {
			out[i] ^= x[i] ^ y[i] ^ t[i]
		}
		return
	}
	for i := range t {
		out[i] = x[i] ^ y[i] ^ t[i]
	}
}

// mixBlamka is Argon2's variant of the BLAKE2b mixing function: each addition
// also folds in the product of the low 32 bits of its operands, which is what
// makes the permutation resist time-memory trade-offs.
func mixBlamka(a, b, c, d uint64) (uint64, uint64, uint64, uint64) {
	a = a + b + 2*uint64(uint32(a))*uint64(uint32(b))
	d = bits.RotateLeft64(d^a, -32)
	c = c + d + 2*uint64(uint32(c))*uint64(uint32(d))
	b = bits.RotateLeft64(b^c, -24)
	a = a + b + 2*uint64(uint32(a))*uint64(uint32(b))
	d = bits.RotateLeft64(d^a, -16)
	c = c + d + 2*uint64(uint32(c))*uint64(uint32(d))
	b = bits.RotateLeft64(b^c, -63)
	return a, b, c, d
}

// blamkaRound applies mixBlamka to sixteen words as a 4x4 matrix: four columns
// then four diagonals.
func blamkaRound(t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15 *uint64) {
	*t00, *t04, *t08, *t12 = mixBlamka(*t00, *t04, *t08, *t12)
	*t01, *t05, *t09, *t13 = mixBlamka(*t01, *t05, *t09, *t13)
	*t02, *t06, *t10, *t14 = mixBlamka(*t02, *t06, *t10, *t14)
	*t03, *t07, *t11, *t15 = mixBlamka(*t03, *t07, *t11, *t15)
	*t00, *t05, *t10, *t15 = mixBlamka(*t00, *t05, *t10, *t15)
	*t01, *t06, *t11, *t12 = mixBlamka(*t01, *t06, *t11, *t12)
	*t02, *t07, *t08, *t13 = mixBlamka(*t02, *t07, *t08, *t13)
	*t03, *t04, *t09, *t14 = mixBlamka(*t03, *t04, *t09, *t14)
}

// bytesToBlock loads a 1024-byte little-endian block into words.
func bytesToBlock(b *argonBlock, src []byte) {
	for i := range b {
		b[i] = binary.LittleEndian.Uint64(src[i*8:])
	}
}

// blockToBytes stores block words into a 1024-byte little-endian buffer.
func blockToBytes(dst *[1024]byte, b *argonBlock) {
	for i, v := range b {
		binary.LittleEndian.PutUint64(dst[i*8:], v)
	}
}
