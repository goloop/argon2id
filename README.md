[![deps.dev](https://img.shields.io/badge/deps.dev-insights-4c8dbc)](https://deps.dev/go/github.com%2Fgoloop%2Fargon2id) [![Go Reference](https://pkg.go.dev/badge/github.com/goloop/argon2id.svg)](https://pkg.go.dev/github.com/goloop/argon2id) [![License](https://img.shields.io/badge/license-MIT-brightgreen?style=flat)](https://github.com/goloop/argon2id/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# argon2id

`argon2id` hashes and verifies passwords with Argon2id (RFC 9106), the
memory-hard function chosen by the Password Hashing Competition. Memory-hard
means computing a hash costs a defined amount of RAM, which is what makes
offline GPU and ASIC cracking of a leaked hash expensive - the property a
password hasher exists to provide.

Argon2id is built on BLAKE2b (RFC 7693), which the standard library does not
ship, so this package implements both from scratch on the standard library
alone. It has **zero dependencies** and its output is pinned to the official RFC
test vectors.

## Features

- **Memory-hard by design** - Argon2id, the hybrid recommended for password
  storage, resisting both side-channel and time-memory-trade-off attacks.
- **Self-describing hashes** - a standard PHC string carries the algorithm,
  version, cost parameters and salt, so `Verify` needs nothing but the string.
- **Tunable cost** - memory, passes and parallelism as functional options, with
  sane defaults and bounds that reject a hostile or malformed hash before it can
  allocate memory.
- **Rehash on login** - `NeedsRehash` reports when a stored hash is weaker than
  your current settings, so you can transparently upgrade it.
- **Zero dependencies** - standard library only; no `cgo`, no third-party code.
- **Pinned to the spec** - validated against the RFC 9106 Argon2id vector and
  the RFC 7693 BLAKE2b vectors.

## Installation

```shell
go get github.com/goloop/argon2id
```

Requires Go 1.24 or newer. The package has no third-party dependencies.

## Quick start

```go
h := argon2id.New()

encoded, err := h.Hash([]byte(password)) // store encoded (a string)
if err != nil {
	// only fails if the system CSPRNG fails
}

err = h.Verify(encoded, []byte(attempt)) // nil on match
if errors.Is(err, argon2id.ErrMismatch) {
	// wrong password
}
```

The encoded value is a PHC string that stands on its own:

```text
$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHR2YWx1ZQ$aGFzaGRpZ2VzdC4uLg
```

Store it as-is. `Verify` reads the parameters and salt back out of it, so you
never manage them separately.

## Tuning the cost

The defaults - 64 MiB of memory, one pass, four lanes - suit an interactive
login on modest hardware. Raise them for higher-value secrets or faster
hardware; the right numbers depend on your latency budget, so measure.

```go
h := argon2id.New(
	argon2id.WithMemory(128*1024), // KiB (128 MiB)
	argon2id.WithTime(3),          // passes over memory
	argon2id.WithThreads(4),       // lanes (parallelism)
)
```

Every option is bounded: values are clamped to a safe range so a hasher can
never be configured to mint a hash its own `Verify` would later reject.

## Upgrading old hashes

Call `NeedsRehash` after a successful `Verify` to raise the cost of stored
hashes as your defaults strengthen over time:

```go
if err := h.Verify(stored, pw); err == nil {
	if h.NeedsRehash(stored) {
		fresh, _ := h.Hash(pw) // persist fresh in place of stored
	}
}
```

## Use with goloop/auth

The `Hasher` method set (`Hash`, `Verify`, `NeedsRehash`) matches the
`PasswordHasher` and `Rehasher` interfaces in
[`goloop/auth`](https://github.com/goloop/auth), so it drops in wherever those
are expected - without either package importing the other:

```go
var hasher auth.PasswordHasher = argon2id.New()
```

Use `goloop/auth` for tokens, refresh rotation and middleware, and this package
for the password hash underneath.

## Correctness

Password hashing is one place where a subtle bug is silent, so the
implementation is checked against published test vectors:

- Argon2id - the RFC 9106 vector (password, salt, secret and associated data).
- BLAKE2b - the RFC 7693 vectors.

If those pass, the construction matches the reference bit for bit. Run them
with `go test ./...`.

## License

MIT - see [LICENSE](LICENSE).
