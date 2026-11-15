package jwt

import (
	"errors"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func accessClaims(audience, typ string) jwtlib.MapClaims {
	now := time.Now()
	return jwtlib.MapClaims{
		"sub": "a1d57572-58e2-4d3f-9ff2-98e9fd47f55f",
		"aud": []string{audience},
		"typ": typ,
		"exp": now.Add(time.Minute).Unix(),
		"nbf": now.Add(-time.Second).Unix(),
		"iat": now.Unix(),
	}
}

func TestParseAccessStrictValidation(t *testing.T) {
	ring, err := NewKeyRing([]string{testPrivatePEM(t)})
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(ring, "https://issuer.example")
	verifier := NewVerifier(ring, "https://issuer.example")

	valid, err := signer.Sign(accessClaims("api", "access"))
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := signer.Sign(accessClaims("api", "refresh"))
	if err != nil {
		t.Fatal(err)
	}
	otherRing, err := NewKeyRing([]string{testPrivatePEM(t)})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := NewSigner(otherRing, "https://issuer.example").Sign(accessClaims("api", "access"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		raw      string
		audience string
		wantErr  error
	}{
		{name: "valid", raw: valid, audience: "api"},
		{name: "wrong audience", raw: valid, audience: "other", wantErr: ErrTokenWrongAudience},
		{name: "wrong type", raw: refresh, audience: "api", wantErr: ErrTokenWrongType},
		{name: "foreign key", raw: foreign, audience: "api", wantErr: ErrTokenMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.ParseAccess(test.raw, test.audience)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ParseAccess() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
