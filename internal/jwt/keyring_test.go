package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func testPrivatePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func TestNewKeyRingAndStableID(t *testing.T) {
	first, second := testPrivatePEM(t), testPrivatePEM(t)
	ring, err := NewKeyRing([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := ring.JWKS()["keys"].([]map[string]any)
	if !ok {
		t.Fatal("JWKS keys field has an unexpected type")
	}
	if got, want := len(keys), 2; got != want {
		t.Fatalf("JWKS key count = %d, want %d", got, want)
	}
	again, err := NewKeyRing([]string{first})
	if err != nil {
		t.Fatal(err)
	}
	if ring.Signing().ID != again.Signing().ID {
		t.Fatal("the same public key produced a different kid")
	}
	if _, ok := ring.ByID(ring.Signing().ID); !ok {
		t.Fatal("signing key is not indexed by kid")
	}
}

func TestNewKeyRingRejectsEmptyAndDuplicates(t *testing.T) {
	if _, err := NewKeyRing(nil); err == nil {
		t.Fatal("expected an error for an empty key ring")
	}
	key := testPrivatePEM(t)
	if _, err := NewKeyRing([]string{key, key}); err == nil {
		t.Fatal("expected an error for a duplicate key")
	}
}
