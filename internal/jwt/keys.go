package jwt

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func normalizeKey(key string) string {
	if strings.Contains(key, `\n`) {
		return strings.ReplaceAll(key, `\n`, "\n")
	}
	return key
}

// ParsePrivateKey parses an RSA private key from PEM. Literal \n sequences are
// converted to newlines so keys can be supplied on a single environment line.
func ParsePrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	normalizedKey := normalizeKey(keyPEM)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(normalizedKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return privateKey, nil
}
