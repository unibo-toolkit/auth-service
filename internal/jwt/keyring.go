package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Key is a single RSA key pair with its ID (kid) for JWKS.
type Key struct {
	ID      string // kid
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// KeyRing contains an ordered set of RSA signing keys. The first key signs new
// tokens, while every key remains available for verification and JWKS output.
type KeyRing struct {
	keys []Key
	byID map[string]Key
}

// NewKeyRing parses private RSA PEM values and builds a key ring. It derives
// each public key and assigns a deterministic kid based on that public key.
func NewKeyRing(privatePEMs []string) (*KeyRing, error) {
	if privatePEMs == nil || len(privatePEMs) == 0 {
		return nil, errors.New("private PEM list is empty")
	}

	rings := &KeyRing{
		keys: make([]Key, 0, len(privatePEMs)),
		byID: make(map[string]Key, len(privatePEMs)),
	}

	for i, pem := range privatePEMs {
		privateKey, err := ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("parse signing key %d: %w", i, err)
		}
		publicKey := &privateKey.PublicKey
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal public key %d: %w", i, err)
		}
		sum := sha256.Sum256(der)
		kid := base64.RawURLEncoding.EncodeToString(sum[:])[:16]

		if _, exists := rings.byID[kid]; exists {
			return nil, fmt.Errorf("duplicate signing key: %s", kid)
		}
		rings.keys = append(rings.keys, Key{
			ID:      kid,
			Private: privateKey,
			Public:  publicKey,
		})
		rings.byID[kid] = rings.keys[len(rings.keys)-1]
	}

	return rings, nil
}

// ByID returns the key associated with kid and reports whether it exists.
func (r *KeyRing) ByID(kid string) (Key, bool) {
	key, ok := r.byID[kid]
	return key, ok
}

// Signing returns the first key in the ring, which is used to sign new tokens.
func (r *KeyRing) Signing() Key {
	return r.keys[0]
}

// JWKS returns an RFC 7517 JSON Web Key Set containing every public key in the
// ring. RSA integers are encoded with unpadded base64url encoding.
func (r *KeyRing) JWKS() map[string]any {
	keys := make([]map[string]any, 0, len(r.keys))
	for _, key := range r.keys {
		modulus := key.Public.N.Bytes()
		exponent := big.NewInt(int64(key.Public.E)).Bytes()

		keys = append(keys, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"kid": key.ID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(modulus),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		})
	}

	return map[string]any{
		"keys": keys,
	}
}
