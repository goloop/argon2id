// Command argon2id hashes and verifies passwords from the shell, with the
// same defaults the library uses.
//
// It exists for the operational moment that has no code around it: seeding a
// database, repairing one account by hand, checking what a stored hash was
// made with. The alternative is a throwaway Go module written to call one
// function, and the cost of that detour is not the typing - it is that the
// throwaway picks its own parameters, so the hash it produces is not the one
// the application would have produced.
//
//	echo -n 'secret' | argon2id hash
//	$argon2id$v=19$m=65536,t=2,p=1$...
//
//	echo -n 'secret' | argon2id verify '$argon2id$v=19$...'   # exit 0 on match
//
//	argon2id params '$argon2id$v=19$...'   # what a stored hash was made with
//
// The password is read from standard input rather than taken as an argument,
// so it does not reach the process list or the shell history. One trailing
// newline is removed, because the usual way to pipe a password in adds one;
// both hash and verify remove it the same way, so a password hashed here
// verifies here.
//
// Cost can be raised with the flags below, and both sides have to agree: a
// hash made with -m 131072 verifies against any settings, but NeedsRehash
// reports it as stale unless the application uses the same ones.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/goloop/argon2id"
)

// exit codes, chosen so a shell can branch on them.
const (
	exitOK       = 0
	exitMismatch = 1 // verify: the password does not match
	exitUsage    = 2 // bad arguments, unreadable input, malformed hash
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main with its edges passed in, so the behaviour can be tested.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("argon2id", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memory := fs.Int("m", 0, "memory cost in KiB (default: the library's)")
	time := fs.Int("t", 0, "passes over memory (default: the library's)")
	threads := fs.Int("p", 0, "lanes (default: the library's)")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return exitUsage
	}

	var opts []argon2id.Option
	if *memory > 0 {
		opts = append(opts, argon2id.WithMemory(*memory))
	}
	if *time > 0 {
		opts = append(opts, argon2id.WithTime(*time))
	}
	if *threads > 0 {
		opts = append(opts, argon2id.WithThreads(*threads))
	}
	h := argon2id.New(opts...)

	switch rest[0] {
	case "hash":
		return hash(h, stdin, stdout, stderr)
	case "verify":
		if len(rest) != 2 {
			fmt.Fprintln(stderr, "argon2id: verify needs one encoded hash")
			return exitUsage
		}
		return verify(h, rest[1], stdin, stderr)
	case "params":
		if len(rest) != 2 {
			fmt.Fprintln(stderr, "argon2id: params needs one encoded hash")
			return exitUsage
		}
		return params(h, rest[1], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "argon2id: unknown command %q\n", rest[0])
		fs.Usage()
		return exitUsage
	}
}

// hash prints the PHC string for the password on standard input.
func hash(h *argon2id.Hasher, stdin io.Reader, stdout, stderr io.Writer) int {
	password, err := readPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "argon2id: %v\n", err)
		return exitUsage
	}

	encoded, err := h.Hash(password)
	if err != nil {
		fmt.Fprintf(stderr, "argon2id: %v\n", err)
		return exitUsage
	}

	fmt.Fprintln(stdout, encoded)
	return exitOK
}

// verify reports through the exit code whether the password matches.
func verify(h *argon2id.Hasher, encoded string, stdin io.Reader, stderr io.Writer) int {
	password, err := readPassword(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "argon2id: %v\n", err)
		return exitUsage
	}

	switch err := h.Verify(encoded, password); {
	case err == nil:
		return exitOK
	case errors.Is(err, argon2id.ErrMismatch):
		// Not an error worth printing: a shell script branches on the exit
		// code, and a message on stderr would have to be filtered out of
		// every log that runs this in a loop.
		return exitMismatch
	default:
		// A malformed hash is a different thing from a wrong password, and
		// silently reporting it as one would send someone resetting an
		// account over a typo in a database field.
		fmt.Fprintf(stderr, "argon2id: %v\n", err)
		return exitUsage
	}
}

// params prints what a stored hash was made with, and whether the current
// settings have moved past it.
func params(h *argon2id.Hasher, encoded string, stdout, stderr io.Writer) int {
	if err := h.Verify(encoded, nil); err != nil &&
		!errors.Is(err, argon2id.ErrMismatch) {
		fmt.Fprintf(stderr, "argon2id: %v\n", err)
		return exitUsage
	}

	// The PHC string carries its own parameters, which is the whole point of
	// the format; printing the middle of it beats explaining the syntax.
	fields := strings.Split(encoded, "$")
	if len(fields) < 4 {
		fmt.Fprintln(stderr, "argon2id: not a PHC-encoded hash")
		return exitUsage
	}
	fmt.Fprintln(stdout, fields[3])

	if h.NeedsRehash(encoded) {
		fmt.Fprintln(stdout, "stale: weaker than the current settings")
	}
	return exitOK
}

// readPassword reads the password from r, dropping one trailing newline.
//
// Exactly one, and only at the end: the usual way to pipe a password in adds
// it, and a password that genuinely ends in a newline would be unusable
// otherwise. Both commands do this identically, so anything hashed here
// verifies here.
func readPassword(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading the password: %w", err)
	}
	// Drop one trailing newline, and the carriage return that precedes it on
	// platforms that send both.
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	return data, nil
}

const usage = `argon2id hashes and verifies passwords with the library's own defaults.

Usage:
  echo -n 'secret' | argon2id [flags] hash
  echo -n 'secret' | argon2id [flags] verify <encoded>
  argon2id params <encoded>

The password is read from standard input so it stays out of the process list
and the shell history. One trailing newline is removed.

Exit codes: 0 ok, 1 password does not match, 2 bad usage or malformed hash.

Flags:
`
