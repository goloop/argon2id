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
- [Command line](#command-line)
- [Timing and enumeration](#timing-and-enumeration)
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
| `WithTime(passes)` | 2 | number of passes over memory |
| `WithThreads(lanes)` | 1 | parallelism (lanes) |
| `WithSaltLength(n)` | 16 | random salt length in bytes |
| `WithKeyLength(n)` | 32 | derived digest length in bytes |

Higher memory and time make each hash slower and each guess costlier; the right
numbers depend on your latency budget and hardware, so measure. Every value is
clamped to a safe range.

The cost is per call, and a wrong password costs exactly as much as a right
one - that symmetry is what a password hash is for. The consequence lands on
the caller: an endpoint that verifies a hundred attempts concurrently at the
defaults spends 6.4 GiB, so bound concurrency at the call site (a semaphore of
eight caps it at 512 MiB) and rate-limit the endpoint. The hasher does not
throttle itself: it cannot know your memory budget, and a hasher that silently
queued would turn a memory ceiling into a latency mystery. `NeedsRehash` is
the cheap exception - it parses the encoded string and derives nothing.

## Encoding

`Hash` returns the standard PHC string:

```text
$argon2id$v=19$m=65536,t=2,p=1$<base64-salt>$<base64-digest>
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

## Command line

`cmd/argon2id` hashes and verifies from a shell with the library's defaults,
for the operational moments that have no code around them - seeding a
database, repairing one account by hand:

```sh
echo -n 'secret' | argon2id hash
echo -n 'secret' | argon2id verify '$argon2id$v=19$...'   # exit 0 on match
argon2id params '$argon2id$v=19$...'                      # cost of a stored hash
```

The password is read from standard input so it stays out of the process list
and the shell history; one trailing newline is dropped identically by both
commands. Exit codes: 0 match, 1 no match, 2 bad usage or a malformed hash -
a malformed hash is deliberately not reported as a wrong password. Using this
rather than a throwaway program matters for one reason: a throwaway picks its
own cost parameters, so the hash it writes is not the one the application
would write.

## Timing and enumeration

A login that hashes only when the account exists answers "no such account"
two orders of magnitude faster than "wrong password", and identical error
messages do not hide it. The fix is to spend the same work on both branches
by verifying against a decoy hash built once at startup with the same
settings; `goloop/auth` ships it as `BurnVerify`, and `NeedsRehash` is what
keeps a long-lived decoy in step with the current parameters.

## Dependencies

None. Standard library only.

## Scope

This package hashes and verifies passwords. It does not manage users, sessions
or tokens; for tokens, refresh rotation and HTTP middleware, use
[`goloop/auth`](https://github.com/goloop/auth), whose `PasswordHasher`
interface this package satisfies.
