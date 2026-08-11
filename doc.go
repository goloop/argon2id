// Package argon2id hashes and verifies passwords with Argon2id (RFC 9106).
//
// Argon2id is memory-hard: computing a hash costs a defined amount of RAM,
// which is what makes offline GPU and ASIC cracking of a leaked hash expensive.
// Argon2 is built on BLAKE2b (RFC 7693), which the standard library does not
// ship, so this package implements both from scratch on the standard library
// alone. It has no third-party dependencies and its output is pinned to the
// official RFC test vectors.
//
// # Hashing
//
//	h := argon2id.New()
//	encoded, err := h.Hash([]byte(password)) // store encoded (a string)
//	err = h.Verify(encoded, []byte(attempt)) // nil on match
//
// The encoded value is a self-describing PHC string
// ($argon2id$v=19$m=...,t=...,p=...$salt$digest): it carries the algorithm,
// version, cost parameters and salt, so Verify needs nothing but the string.
//
// # Cost
//
//	h := argon2id.New(
//	    argon2id.WithMemory(128*1024), // KiB
//	    argon2id.WithTime(3),          // passes
//	    argon2id.WithThreads(4),       // lanes
//	)
//
// The defaults (64 MiB, two passes, one lane) suit an interactive login on
// modest hardware. Every option is bounded, so a hasher can never be configured
// to mint a hash its own Verify would reject.
//
// The memory cost is paid on every call, and a wrong password costs exactly as
// much as a right one - that symmetry is the point of a password hash, not an
// oversight. It also means the caller, not this package, decides how many
// verifications may run at once: a login endpoint that accepts a hundred
// concurrent attempts at the default cost has just agreed to spend 6.4 GiB.
// Bound concurrency at the call site - a semaphore of eight puts the ceiling
// at half a gigabyte - and rate-limit the endpoint; the hasher itself has no
// business refusing work. NeedsRehash is the exception: it only parses the
// encoded string and costs nothing.
//
// # Rehashing
//
//	if err := h.Verify(stored, pw); err == nil {
//	    if h.NeedsRehash(stored) {
//	        fresh, _ := h.Hash(pw) // persist fresh in place of stored
//	    }
//	}
//
// NeedsRehash reports when a stored hash is weaker than the current settings, so
// a successful login can transparently upgrade it as defaults strengthen.
//
// # Interop
//
// The Hasher method set (Hash, Verify, NeedsRehash) matches the PasswordHasher
// and Rehasher interfaces in goloop/auth, so it can be used through them without
// either package importing the other.
//
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package argon2id
