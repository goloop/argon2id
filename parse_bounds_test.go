package argon2id

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRejectsOversizedHash(t *testing.T) {
	if _, err := parse(strings.Repeat("$", 1<<16)); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkParseEncodedHash(b *testing.B) {
	for _, tt := range []struct{ name, hash string }{
		{"valid", "$argon2id$v=19$m=65536,t=2,p=1$" + strings.Repeat("Y", 22) + "$" + strings.Repeat("Y", 43)},
		{"oversized", strings.Repeat("$", 1<<16)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = parse(tt.hash)
			}
		})
	}
}
