# argon2id - reference

`argon2id` is a memory-hard password hasher built on Argon2id (RFC 9106). Full
English reference; Ukrainian in [DOC.UK.md](DOC.UK.md).

## Contents

- [Overview](#overview)
- [Hashing and verifying](#hashing-and-verifying)
- [Cost parameters](#cost-parameters)
- [Encoding](#encoding)
- [Rehashing](#rehashing)
- [Bounds and validation](#bounds-and-validation)
- [Correctness](#correctness)
- [Dependencies](#dependencies)
- [Scope](#scope)

## Overview

Argon2id is the hybrid variant recommended for password storage: it combines
Argon2i's data-independent addressing (resistant to side-channel timing) for the
first half of the first pass with Argon2d's data-dependent addressing
(resistant to time-memory trade-offs) for the rest. It is memory-hard, so an
attacker who steals a hash must spend real RAM per guess to crack it offline.

The package implements Argon2id and its underlying BLAKE2b (RFC 7693) directly
on the standard library, with no third-party code.

## Hashing and verifying

```go
h := argon2id.New()

encoded, err := h.Hash([]byte(password)) // store encoded
err = h.Verify(encoded, []byte(attempt)) // nil on match
```

`Hash` draws a fresh random salt from the system CSPRNG (`crypto/rand`) and
returns a self-describing string. `Verify` reads the parameters and salt back
out of that string, recomputes the digest, and compares it in constant time
(`crypto/subtle`). A wrong password returns `ErrMismatch`; a malformed or
out-of-bounds hash returns `ErrInvalidHash`.

## Cost parameters

```go
h := argon2id.New(
	argon2id.WithMemory(128*1024), // KiB (128 MiB)
	argon2id.WithTime(3),          // passes over memory
	argon2id.WithThreads(4),       // lanes (parallelism)
	argon2id.WithSaltLength(16),   // random salt bytes
	argon2id.WithKeyLength(32),    // derived digest bytes
)
```

| Option | Default | Meaning |
|---|---|---|
| `WithMemory(kib)` | 65536 (64 MiB) | memory cost in KiB |
| `WithTime(passes)` | 1 | number of passes over memory |
| `WithThreads(lanes)` | 4 | parallelism (lanes) |
| `WithSaltLength(n)` | 16 | random salt length in bytes |
| `WithKeyLength(n)` | 32 | derived digest length in bytes |

Higher memory and time make each hash slower and each guess costlier; the right
numbers depend on your latency budget and hardware, so measure. Every value is
clamped to a safe range.

## Encoding

`Hash` returns the standard PHC string:

```text
$argon2id$v=19$m=65536,t=1,p=4$<base64-salt>$<base64-digest>
```

Salt and digest are `base64.RawStdEncoding` (no padding). Store the whole string
in one column; there are no separate parameters to track.

## Rehashing

`NeedsRehash` reports whether a stored hash is weaker than the hasher's current
settings, so a successful login can transparently strengthen it:

```go
if err := h.Verify(stored, pw); err == nil {
	if h.NeedsRehash(stored) {
		fresh, _ := h.Hash(pw) // persist fresh in place of stored
	}
}
```

It returns true for a malformed hash or one whose memory, time, salt or key
length is below the current settings.

## Bounds and validation

An encoded hash is fully validated before any memory is allocated. The parser
rejects a wrong algorithm or version, a parameter field with trailing garbage,
and any cost outside these bounds:

| Parameter | Min | Max |
|---|---|---|
| memory | 8 x lanes KiB | 1 GiB |
| time | 1 | 64 |
| threads | 1 | 255 |
| salt | 8 bytes | 64 bytes |
| digest | 16 bytes | 128 bytes |

Field lengths are checked before base64 decoding, so an oversized field cannot
force a large allocation. The ceilings are operational: they sit well above any
sane cost while bounding what a single `Verify` can be made to consume.

## Correctness

The implementation is pinned to published test vectors, run by `go test`:

- Argon2id - the RFC 9106 vector (password, salt, secret and associated data).
- BLAKE2b - the RFC 7693 vectors, including the empty input.

A passing vector means the construction matches the reference bit for bit.

## Dependencies

None. Standard library only.

## Scope

This package hashes and verifies passwords. It does not manage users, sessions
or tokens; for tokens, refresh rotation and HTTP middleware, use
[`goloop/auth`](https://github.com/goloop/auth), whose `PasswordHasher`
interface this package satisfies.
