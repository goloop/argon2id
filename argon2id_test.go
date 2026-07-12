package argon2id

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestBlake2bVector pins the BLAKE2b primitive to the RFC 7693 Appendix A
// "abc" vector, so a regression in the hash surfaces here rather than as a
// silent Argon2 mismatch.
func TestBlake2bVector(t *testing.T) {
	want, _ := hex.DecodeString(
		"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
			"7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
	var got [64]byte
	blake2bSum(got[:], []byte("abc"))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("BLAKE2b(\"abc\") = %x, want %x", got[:], want)
	}
}

// TestBlake2bEmpty pins the empty-input digest, exercising the final-block path
// with a zero counter.
func TestBlake2bEmpty(t *testing.T) {
	want, _ := hex.DecodeString(
		"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
			"d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
	var got [64]byte
	blake2bSum(got[:], nil)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("BLAKE2b(\"\") = %x, want %x", got[:], want)
	}
}

// TestRFC9106Vector pins the whole Argon2id construction to the official RFC
// 9106 test vector (password, salt, secret and associated data all set). If
// this passes, the implementation matches the reference bit for bit.
func TestRFC9106Vector(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	secret := bytes.Repeat([]byte{0x03}, 8)
	data := bytes.Repeat([]byte{0x04}, 12)

	got := deriveKey(password, salt, secret, data, 3, 32, 4, 32)
	want, _ := hex.DecodeString(
		"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
	if !bytes.Equal(got, want) {
		t.Fatalf("Argon2id RFC 9106 vector = %x, want %x", got, want)
	}
}

// TestRoundTrip exercises the hasher surface: a hash verifies against the right
// password, rejects a wrong one, and carries the expected PHC shape.
func TestRoundTrip(t *testing.T) {
	// Small parameters keep the test fast; correctness is cost-independent.
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	encoded, err := h.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix([]byte(encoded), []byte("$argon2id$v=19$m=256,t=1,p=1$")) {
		t.Fatalf("unexpected encoding: %s", encoded)
	}
	if err := h.Verify(encoded, []byte("correct horse battery staple")); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	if err := h.Verify(encoded, []byte("wrong")); err == nil {
		t.Error("wrong password accepted")
	}
}

// TestVerifyRejectsMalformed checks the bounds-checking parser, including the
// trailing-garbage and out-of-range cases raised in review.
func TestVerifyRejectsMalformed(t *testing.T) {
	h := New()
	valid := "YWJjZGVmZ2hpamtsbW5vcA" // 16 bytes, base64 raw-std
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=256,t=1,p=1$short$short",
		"$argon2i$v=19$m=256,t=1,p=1$" + valid + "$" + valid,       // wrong variant
		"$argon2id$v=18$m=256,t=1,p=1$" + valid + "$" + valid,      // wrong version
		"$argon2id$v=19$m=256,t=1,p=1xxx$" + valid + "$" + valid,   // trailing garbage
		"$argon2id$v=19$m=99999999,t=1,p=1$" + valid + "$" + valid, // memory over ceiling
		"$argon2id$v=19$m=256,t=999,p=1$" + valid + "$" + valid,    // time over ceiling
	} {
		if err := h.Verify(bad, []byte("pw")); err == nil {
			t.Errorf("malformed hash accepted: %q", bad)
		}
	}
}

// TestLowMemoryStillRoundTrips guards the fix for a below-floor memory option:
// New clamps the memory up to Argon2's floor, so Hash never mints a hash its
// own Verify would reject.
func TestLowMemoryStillRoundTrips(t *testing.T) {
	h := New(WithMemory(1), WithThreads(1))
	encoded, err := h.Hash([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(encoded, []byte("pw")); err != nil {
		t.Fatalf("hash minted with a low memory option failed its own verify: %v", err)
	}
}

// TestSaltIsRandom confirms two hashes of the same password differ (a fresh
// salt each time) yet both verify.
func TestSaltIsRandom(t *testing.T) {
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	a, err := h.Hash([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Hash([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical - salt is not random")
	}
	if h.Verify(a, []byte("same")) != nil || h.Verify(b, []byte("same")) != nil {
		t.Fatal("a randomly salted hash failed to verify")
	}
}

// TestErrMismatchIsTyped confirms a wrong password returns the exported error.
func TestErrMismatchIsTyped(t *testing.T) {
	h := New(WithMemory(256), WithTime(1), WithThreads(1))
	encoded, _ := h.Hash([]byte("pw"))
	if err := h.Verify(encoded, []byte("nope")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password error = %v, want ErrMismatch", err)
	}
}

// TestNeedsRehash confirms an old, weaker hash is flagged for upgrade while a
// current one is not.
func TestNeedsRehash(t *testing.T) {
	weak := New(WithMemory(256), WithTime(1), WithThreads(1))
	strong := New(WithMemory(1024), WithTime(2), WithThreads(1))

	encoded, err := weak.Hash([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if !strong.NeedsRehash(encoded) {
		t.Error("a weaker hash should need a rehash under stronger settings")
	}
	if weak.NeedsRehash(encoded) {
		t.Error("a hash should not need a rehash under its own settings")
	}
}
