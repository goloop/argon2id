# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-10-18

Reject oversized encoded hashes before allocating parser fields.

## [1.1.1] - 2026-08-11

Patch release: this changelog, and the reference catching up.

### Documentation
- The module gains the changelog it should have had, reconstructing the
  releases below from the git history.
- The reference covers `cmd/argon2id` and the timing-oracle note, which until
  now lived only in the godoc.

## [1.1.0] - 2026-08-11

Minor release: a command line for the operational moments.

### Added
- `cmd/argon2id` hashes and verifies from a shell with the library's own
  defaults, and `params` reports what a stored hash was made with and whether
  it has fallen behind the current settings. The password travels through
  standard input, one trailing newline is dropped identically by both
  commands, and the exit codes separate match, mismatch and a hash that could
  not be read at all.

## [1.0.1] - 2026-08-11

Patch release: documentation.

### Documentation
- The cost is stated plainly as per call: a wrong password costs exactly as
  much as a right one, by design, so the caller bounds concurrency (a
  semaphore and a rate limit) and the hasher deliberately does not throttle
  itself. `NeedsRehash` is noted as the cheap exception.

## [1.0.0] - 2026-08-11

First stable release: Argon2id (RFC 9106) and the BLAKE2b it stands on,
implemented from scratch on the standard library, pinned to the official test
vectors. `Hash`/`Verify`/`NeedsRehash` match the `PasswordHasher` and
`Rehasher` interfaces in goloop/auth without either package importing the
other; every cost option is clamped so a hasher can never mint a hash its own
`Verify` would reject.
