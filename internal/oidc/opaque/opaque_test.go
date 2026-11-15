package opaque

import (
	"encoding/base64"
	"testing"
)

func TestNewAndHash(t *testing.T) {
	raw, hash, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" {
		t.Fatal("raw token and hash must not be empty")
	}
	if Hash(raw) != hash {
		t.Fatal("Hash(raw) differs from the hash returned by New")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("token is not valid unpadded base64url: %v", err)
	}
	if got, want := len(decoded), 32; got != want {
		t.Fatalf("decoded token length = %d, want %d", got, want)
	}
	raw2, _, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if raw == raw2 {
		t.Fatal("two generated tokens are equal")
	}
}
