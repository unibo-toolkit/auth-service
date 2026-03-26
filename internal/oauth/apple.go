package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type AppleProvider struct {
	config     *oauth2.Config
	teamID     string
	keyID      string
	privateKey *ecdsa.PrivateKey
}

type appleClaims struct {
	jwt.RegisteredClaims
}

type appleUserInfo struct {
	jwt.RegisteredClaims
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

type appleUserData struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
	Email string `json:"email"`
}

func NewAppleProvider(clientID, teamID, keyID, privateKeyPEM, redirectURL string) (*AppleProvider, error) {
	privateKey, err := parseApplePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Apple private key: %w", err)
	}

	return &AppleProvider{
		config: &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: redirectURL,
			Scopes:      []string{"name", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://appleid.apple.com/auth/authorize",
				TokenURL: "https://appleid.apple.com/auth/token",
			},
		},
		teamID:     teamID,
		keyID:      keyID,
		privateKey: privateKey,
	}, nil
}

func parseApplePrivateKey(keyPEM string) (*ecdsa.PrivateKey, error) {
	normalizedKey := normalizeKey(keyPEM)

	block, _ := pem.Decode([]byte(normalizedKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA private key")
	}

	return ecdsaKey, nil
}

func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.ReplaceAll(key, `\n`, "\n")
	key = strings.ReplaceAll(key, "\r", "")
	return key
}

func (p *AppleProvider) generateClientSecret() (string, error) {
	now := time.Now()
	claims := appleClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.teamID,
			Subject:   p.config.ClientID,
			Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
			ExpiresAt: jwt.NewNumericDate(now.Add(180 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID

	return token.SignedString(p.privateKey)
}

func (p *AppleProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.SetAuthURLParam("response_mode", "form_post"))
}

func (p *AppleProvider) ExchangeCode(code string, additionalData string) (UserInfo, error) {
	ctx := context.Background()

	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to generate client secret: %w", err)
	}

	p.config.ClientSecret = clientSecret

	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return UserInfo{}, fmt.Errorf("%w: %v", ErrCodeExchange, err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return UserInfo{}, fmt.Errorf("%w: missing id_token", ErrUserInfo)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, err := parser.ParseUnverified(idToken, &appleUserInfo{})
	if err != nil {
		return UserInfo{}, fmt.Errorf("%w: failed to parse id_token: %v", ErrUserInfo, err)
	}

	claims, ok := parsedToken.Claims.(*appleUserInfo)
	if !ok {
		return UserInfo{}, fmt.Errorf("%w: invalid claims", ErrUserInfo)
	}

	displayName := claims.Email
	for idx := 0; idx < len(displayName); idx++ {
		if displayName[idx] == '@' {
			displayName = displayName[:idx]
			break
		}
	}

	if additionalData != "" {
		var userData appleUserData
		if err := json.Unmarshal([]byte(additionalData), &userData); err == nil {
			if userData.Name.FirstName != "" {
				displayName = userData.Name.FirstName
				if userData.Name.LastName != "" {
					displayName += " " + userData.Name.LastName
				}
			}
		}
	}

	return UserInfo{
		ID:          claims.Sub,
		Email:       claims.Email,
		DisplayName: displayName,
		AvatarURL:   "",
		Provider:    "apple",
	}, nil
}
