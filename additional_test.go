package argon2id

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"
)

// mustHex decodes a hex fixture or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}

// TestBlake2bDigestLengths pins BLAKE2b at output lengths other than 64,
// exercising the parameter block's length field. Fixtures are cross-checked
// against an independent BLAKE2b implementation.
func TestBlake2bDigestLengths(t *testing.T) {
	cases := []struct {
		size int
		want string
	}{
		{16, "cf4ab791c62b8d2b2109c90275287816"},
		{32, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
		{48, "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"},
	}
	for _, c := range cases {
		got := make([]byte, c.size)
		blake2bSum(got, []byte("abc"))
		if !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("BLAKE2b-%d(abc) = %x, want %s", c.size*8, got, c.want)
		}
	}
}

// TestBlake2bBlockBoundaries exercises the final-block and multi-block counter
// paths with inputs sized around the 128-byte block boundary.
func TestBlake2bBlockBoundaries(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{128, "4daa2fbce753f4a1c1662d050235c8ee0cad24688226ae169db6626956a84c81a32a9aa0d55c6c1445ef869203b99fc0bdc7b92216b3125e58443677c66a9c02"},
		{129, "ce03406b4c6d96efe7c5adb9c32395a5b72f515235b0f24a994dcb06e519e18775de38d310a26d9fc9f860033f01c9b21fd91efd48573e386456ec9d5edf32c9"},
		{256, "2919ecebfd037c98aa401007908afceb73ed166a707aade89f3a0e7ecd5ec8c7fd0bbc9956444b20e77527d06e6597ee9e78d34c9c0c72774805a491182d8d49"},
		{300, "b5c0f0fda5d645b08b3f1857b408e0675517f0626ee84873c6c9049fa3ce8b9f912e51f6f2a7dfa8caace09c5811e7f73b3d9809c1360f7f90b34653b751a884"},
	}
	for _, c := range cases {
		got := make([]byte, 64)
		blake2bSum(got, bytes.Repeat([]byte{0xAB}, c.n))
		if !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("BLAKE2b-512(0xAB*%d) = %x, want %s", c.n, got, c.want)
		}
	}
}

// TestArgon2idMultiLaneVector pins a second, independent Argon2id fixture with a
// multi-pass, multi-lane configuration (t=2, m=256, p=2), cross-checked against
// an independent Argon2id implementation. The RFC 9106 vector covers one shape;
// this covers another.
func TestArgon2idMultiLaneVector(t *testing.T) {
	got := deriveKey([]byte("password"), bytes.Repeat([]byte{0x02}, 16), nil, nil, 2, 256, 2, 32)
	want := "d4361dbd195edb1f63d85da3aaa202591ed5a83b2258e7b51d9b48c8f1eda50b"
	if !bytes.Equal(got, mustHex(t, want)) {
		t.Fatalf("Argon2id(t=2,m=256,p=2) = %x, want %s", got, want)
	}
}

// TestDeriveKeyDeterministic confirms the same inputs always produce the same
// digest (no hidden state).
func TestDeriveKeyDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x05}, 16)
	a := deriveKey([]byte("pw"), salt, nil, nil, 1, 256, 1, 32)
	b := deriveKey([]byte("pw"), salt, nil, nil, 1, 256, 1, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("deriveKey is not deterministic for identical inputs")
	}
}

// TestParameterSensitivity confirms that changing any input changes the digest.
func TestParameterSensitivity(t *testing.T) {
	salt := bytes.Repeat([]byte{0x05}, 16)
	base := deriveKey([]byte("pw"), salt, nil, nil, 2, 256, 2, 32)

	other := bytes.Repeat([]byte{0x06}, 16)
	variants := map[string][]byte{
		"password": deriveKey([]byte("px"), salt, nil, nil, 2, 256, 2, 32),
		"salt":     deriveKey([]byte("pw"), other, nil, nil, 2, 256, 2, 32),
		"time":     deriveKey([]byte("pw"), salt, nil, nil, 3, 256, 2, 32),
		"memory":   deriveKey([]byte("pw"), salt, nil, nil, 2, 512, 2, 32),
		"threads":  deriveKey([]byte("pw"), salt, nil, nil, 2, 256, 1, 32),
	}
	for name, v := range variants {
		if bytes.Equal(base, v) {
			t.Errorf("changing %s did not change the digest", name)
		}
	}
	// A longer key must not merely be a prefix of a shorter one.
	long := deriveKey([]byte("pw"), salt, nil, nil, 2, 256, 2, 64)
	if bytes.Equal(long[:32], base) {
		t.Error("key-length change produced a prefix, not an independent digest")
	}
}

// TestParseRejectionTable hardens the encoded-hash parser against a range of
// malformed inputs. A valid hash is mutated so only the tested defect differs.
func TestParseRejectionTable(t *testing.T) {
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	valid, err := h.Hash([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	// valid == $argon2id$v=19$m=256,t=1,p=1$<salt>$<digest>
	parts := func(s string) []string { return bytesSplit(s) }
	p := parts(valid)
	salt, digest := p[4], p[5]

	bad := []string{
		"",
		"$argon2id$v=19$m=256,t=1,p=1$" + salt, // wrong segment count (5)
		"$argon2id$v=19$m=256,t=1,p=0$" + salt + "$" + digest,   // p=0
		"$argon2id$v=19$m=4,t=1,p=1$" + salt + "$" + digest,     // memory below 8*p floor
		"$argon2id$v=19$m=-1,t=1,p=1$" + salt + "$" + digest,    // negative memory
		"$argon2id$v=19$t=1,m=256,p=1$" + salt + "$" + digest,   // reordered params
		"$argon2id$v=19$m=256,t=1,p=1x$" + salt + "$" + digest,  // trailing garbage
		"$argon2id$v=19$m=256,t=1,p=1$$" + digest,               // empty salt field
		"$argon2id$v=19$m=256,t=1,p=1$" + salt + "$",            // empty digest field
		"$argon2id$v=19$m=256,t=1,p=1$!!!bad!!!$" + digest,      // non-base64 salt
		"$argon2id$v=19$m=256,t=1,p=1$" + salt + "==$" + digest, // padded base64 (raw rejects)
		"$argon2id$v=20$m=256,t=1,p=1$" + salt + "$" + digest,   // wrong version
		"$argon2d$v=19$m=256,t=1,p=1$" + salt + "$" + digest,    // wrong variant
	}
	for i, s := range bad {
		if err := h.Verify(s, []byte("pw")); err == nil {
			t.Errorf("case %d accepted malformed hash: %q", i, s)
		}
	}
}

// bytesSplit splits a PHC string on '$'.
func bytesSplit(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '$' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

// TestConcurrentUse confirms a single Hasher is safe to share across goroutines
// (it is immutable after New). Run with -race.
func TestConcurrentUse(t *testing.T) {
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	encoded, err := h.Hash([]byte("shared"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc, err := h.Hash([]byte("shared"))
			if err != nil {
				t.Errorf("concurrent hash: %v", err)
				return
			}
			if h.Verify(enc, []byte("shared")) != nil {
				t.Error("concurrent verify of own hash failed")
			}
			if h.Verify(encoded, []byte("shared")) != nil {
				t.Error("concurrent verify of shared hash failed")
			}
		}()
	}
	wg.Wait()
}

// TestNeedsRehashThreads guards the fix: a hash with lower parallelism than the
// current hasher must be flagged for a rehash.
func TestNeedsRehashThreads(t *testing.T) {
	weak := New(WithMemory(256), WithTime(1), WithThreads(1))
	strong := New(WithMemory(256), WithTime(1), WithThreads(4))
	encoded, err := weak.Hash([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if !strong.NeedsRehash(encoded) {
		t.Error("a hash with fewer lanes should need a rehash under higher parallelism")
	}
}

// FuzzVerify asserts the parser never panics and only ever rejects or matches.
func FuzzVerify(f *testing.F) {
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	enc, _ := h.Hash([]byte("seed"))
	f.Add(enc)
	f.Add("$argon2id$v=19$m=256,t=1,p=1$short$short")
	f.Add("")
	f.Fuzz(func(t *testing.T, encoded string) {
		_ = h.Verify(encoded, []byte("seed")) // must not panic
		_ = h.NeedsRehash(encoded)            // must not panic
	})
}

// BenchmarkHash measures a hash at small test parameters; raise them to profile
// production cost.
func BenchmarkHash(b *testing.B) {
	h := New(WithMemory(4096), WithTime(1), WithThreads(1))
	pw := []byte("correct horse battery staple")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.Hash(pw); err != nil {
			b.Fatal(err)
		}
	}
}
