package main

import (
	"bytes"
	"strings"
	"testing"
)

// fast keeps the tests quick without changing what is being tested: the
// command's plumbing, not Argon2's cost.
var fast = []string{"-m", "8192", "-t", "1"}

func exec(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// The point of the command is that its hashes are the application's hashes,
// so a round trip through it has to succeed.
func TestHashThenVerify(t *testing.T) {
	code, out, errOut := exec(t, "secret", append(fast, "hash")...)
	if code != exitOK {
		t.Fatalf("hash exited %d: %s", code, errOut)
	}

	encoded := strings.TrimSpace(out)
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("hash printed %q, want a PHC string", encoded)
	}

	if code, _, errOut := exec(t, "secret", append(fast, "verify", encoded)...); code != exitOK {
		t.Errorf("verify of the right password exited %d: %s", code, errOut)
	}
}

// A wrong password is an exit code, not an error message: the caller is a
// shell script, and a line on stderr would have to be filtered out of every
// log that runs this in a loop.
func TestVerifyWrongPassword(t *testing.T) {
	_, out, _ := exec(t, "secret", append(fast, "hash")...)
	encoded := strings.TrimSpace(out)

	code, _, errOut := exec(t, "different", append(fast, "verify", encoded)...)
	if code != exitMismatch {
		t.Errorf("verify of a wrong password exited %d, want %d", code, exitMismatch)
	}
	if errOut != "" {
		t.Errorf("a wrong password printed %q to stderr", errOut)
	}
}

// A malformed hash is a different thing from a wrong password, and reporting
// it as one would send someone resetting an account over a typo in a column.
func TestVerifyMalformedHash(t *testing.T) {
	code, _, errOut := exec(t, "secret", append(fast, "verify", "not-a-hash")...)
	if code != exitUsage {
		t.Errorf("verify of a malformed hash exited %d, want %d", code, exitUsage)
	}
	if errOut == "" {
		t.Error("a malformed hash was rejected without saying why")
	}
}

// The newline a shell adds must not become part of the password, and both
// commands have to agree about it or nothing round-trips.
func TestTrailingNewlineIsDropped(t *testing.T) {
	_, out, _ := exec(t, "secret", append(fast, "hash")...)
	encoded := strings.TrimSpace(out)

	for _, stdin := range []string{"secret\n", "secret\r\n"} {
		if code, _, _ := exec(t, stdin, append(fast, "verify", encoded)...); code != exitOK {
			t.Errorf("a password piped as %q did not verify", stdin)
		}
	}

	// Only one, and only at the end: an interior newline is part of the
	// password.
	if code, _, _ := exec(t, "sec\nret", append(fast, "verify", encoded)...); code == exitOK {
		t.Error("an interior newline was stripped out of the password")
	}
}

func TestParamsReportsWhatAHashWasMadeWith(t *testing.T) {
	_, out, _ := exec(t, "secret", "-m", "8192", "-t", "1", "hash")
	encoded := strings.TrimSpace(out)

	code, out, errOut := exec(t, "", "params", encoded)
	if code != exitOK {
		t.Fatalf("params exited %d: %s", code, errOut)
	}
	if !strings.Contains(out, "m=8192") || !strings.Contains(out, "t=1") {
		t.Errorf("params printed %q, want the cost the hash carries", out)
	}

	// Read against the library's defaults, that hash is behind them, and
	// saying so is the reason to have this at all.
	if !strings.Contains(out, "stale") {
		t.Errorf("params did not report a weaker hash as stale: %q", out)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"frobnicate"}},
		{"verify without a hash", []string{"verify"}},
		{"params without a hash", []string{"params"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, _, _ := exec(t, "", tt.args...); code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}
		})
	}
}
