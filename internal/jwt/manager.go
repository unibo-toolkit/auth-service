package jwt

import (
	"errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

var (
	// ErrTokenMalformed indicates that a token cannot be parsed or its signature
	// and protected header cannot be validated.
	ErrTokenMalformed = errors.New("token malformed")
	// ErrTokenExpired indicates that a token's expiration time has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenWrongType indicates that typ is not "access".
	ErrTokenWrongType = errors.New("token has wrong type")
	// ErrTokenWrongAudience indicates that the required audience is absent.
	ErrTokenWrongAudience = errors.New("token has wrong audience")
)

// Signer creates RS256 JWTs with the active key from a KeyRing.
type Signer struct {
	ring   *KeyRing
	issuer string
}

// NewSigner returns a signer that writes issuer into every signed token.
func NewSigner(ring *KeyRing, issuer string) *Signer {
	return &Signer{ring: ring, issuer: issuer}
}

// Sign signs claims with RS256, sets iss, and places the active key ID in the
// protected JWT header. Sign mutates claims by setting its "iss" entry.
func (s *Signer) Sign(claims jwtlib.MapClaims) (string, error) {
	key := s.ring.Signing()
	claims["iss"] = s.issuer
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID
	return token.SignedString(key.Private)
}

// Verifier parses access tokens using the public keys in a KeyRing.
type Verifier struct {
	ring   *KeyRing
	issuer string
}

// NewVerifier returns a verifier that accepts tokens from issuer.
func NewVerifier(ring *KeyRing, issuer string) *Verifier {
	return &Verifier{ring: ring, issuer: issuer}
}

// AccessClaims contains the registered and service-specific access-token claims.
type AccessClaims struct {
	jwtlib.RegisteredClaims
	Typ      string   `json:"typ"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	Roles    []string `json:"roles"`
}

// ParseAccess validates an RS256 access token, including its key ID, signature,
// issuer, expiration, not-before time, type, and required audience.
func (v *Verifier) ParseAccess(raw, audience string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	_, err := jwtlib.ParseWithClaims(raw, claims, func(token *jwtlib.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrTokenMalformed)
		}
		key, ok := v.ring.ByID(kid)
		if !ok {
			return nil, fmt.Errorf("%w: unknown kid", ErrTokenMalformed)
		}
		return key.Public, nil
	}, jwtlib.WithValidMethods([]string{jwtlib.SigningMethodRS256.Alg()}), jwtlib.WithIssuer(v.issuer), jwtlib.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwtlib.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	if claims.Typ != "access" {
		return nil, ErrTokenWrongType
	}
	matchesAudience := false
	for _, candidate := range claims.Audience {
		if candidate == audience {
			matchesAudience = true
			break
		}
	}
	if !matchesAudience {
		return nil, ErrTokenWrongAudience
	}
	return claims, nil
}
