package opaque

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// New generates a 256-bit opaque token and returns both its base64url value and
// the hash suitable for persistent storage.
func New() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, Hash(raw), nil
}

// Hash returns the unpadded base64url encoding of SHA-256 over raw.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
