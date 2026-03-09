package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func normalizeKey(key string) string {
	if strings.Contains(key, `\n`) {
		return strings.ReplaceAll(key, `\n`, "\n")
	}
	return key
}

func ParsePrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	normalizedKey := normalizeKey(keyPEM)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(normalizedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return privateKey, nil
}

func ParsePublicKey(keyPEM string) (*rsa.PublicKey, error) {
	normalizedKey := normalizeKey(keyPEM)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(normalizedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	return publicKey, nil
}

func GenerateJWKS(publicKey *rsa.PublicKey, keyID string) map[string]interface{} {
	n := publicKey.N.Bytes()
	e := big.NewInt(int64(publicKey.E)).Bytes()

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": keyID,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(n),
				"e":   base64.RawURLEncoding.EncodeToString(e),
			},
		},
	}
}
