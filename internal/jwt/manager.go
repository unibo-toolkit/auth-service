package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/unibo-toolkit/auth-service/internal/config"
)

type Manager struct {
	log        *slog.Logger
	PublicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	issuer     string
	audience   string
	accessTTL  int64
	refreshTTL int64
	kid        string
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	UserID uuid.UUID `json:"uid"`
	Email  string    `json:"email"`
	Roles  []string  `json:"roles"`
}

type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	UserID   uuid.UUID `json:"uid"`
	FamilyID uuid.UUID `json:"fid"`
}

func MustNewJwtManager(log *slog.Logger, cfg *config.Config) *Manager {
	log = log.With("op", "jwt.MustNewJwtManager")
	log.Info("Initializing JWT Manager")

	privateKey, err := ParsePrivateKey(cfg.JWT.PrivateKey)
	if err != nil {
		log.Error("Failed to parse RSA private key", "error", err)
		panic(err)
	}

	publicKey, err := ParsePublicKey(cfg.JWT.PublicKey)
	if err != nil {
		log.Error("Failed to parse RSA public key", "error", err)
		panic(err)
	}

	derivedPublicKey := privateKey.Public().(*rsa.PublicKey)
	if derivedPublicKey.N.Cmp(publicKey.N) != 0 || derivedPublicKey.E != publicKey.E {
		log.Error("Public key does not match private key")
		panic("Public key does not match private key")
	}

	log.Info("JWT Manager initialized successfully")

	return &Manager{
		log:        log,
		PublicKey:  publicKey,
		privateKey: privateKey,
		issuer:     cfg.JWT.Issuer,
		audience:   cfg.JWT.Audience,
		accessTTL:  cfg.JWT.AccessTokenTTL,
		refreshTTL: cfg.JWT.RefreshTokenTTL,
		kid:        cfg.JWT.Kid,
	}
}

func (m *Manager) GenerateAccessToken(userID uuid.UUID, email string, roles []string) (string, error) {
	now := time.Now()
	log := m.log.With("op", "jwt.GenerateAccessToken", "user_id", userID)
	log.Info("Generating new access token")

	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(m.accessTTL) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID: userID,
		Email:  email,
		Roles:  roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid

	tokenString, err := token.SignedString(m.privateKey)
	if err != nil {
		log.Error("Failed to sign access token", "error", err)
		return "", err
	}

	log.Info("Access token generated successfully", "expires_at", claims.ExpiresAt)
	return tokenString, nil
}

func (m *Manager) GenerateRefreshToken(userID, familyID uuid.UUID) (string, error) {
	now := time.Now()
	log := m.log.With("op", "jwt.GenerateRefreshToken", "user_id", userID)
	log.Info("Generating new refresh token")

	claims := &RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(m.refreshTTL) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:   userID,
		FamilyID: familyID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid

	tokenString, err := token.SignedString(m.privateKey)
	if err != nil {
		log.Error("Failed to sign refresh token", "error", err)
		return "", err
	}

	log.Info("Refresh token generated successfully")
	return tokenString, nil
}

func (m *Manager) validateToken(tokenString string, claims jwt.Claims, log *slog.Logger) error {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			log.Error("Unexpected signing method", "alg", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.PublicKey, nil
	})

	if err != nil {
		log.Error("Failed to parse token", "error", err)
		return err
	}

	if !token.Valid {
		log.Error("Invalid token")
		return fmt.Errorf("invalid token")
	}

	return nil
}

func (m *Manager) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	log := m.log.With("op", "jwt.ValidateAccessToken")
	claims := &AccessTokenClaims{}

	if err := m.validateToken(tokenString, claims, log); err != nil {
		return nil, err
	}

	log.Info("Valid access token")
	return claims, nil
}

func (m *Manager) ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	log := m.log.With("op", "jwt.ValidateRefreshToken")
	claims := &RefreshTokenClaims{}

	if err := m.validateToken(tokenString, claims, log); err != nil {
		return nil, err
	}

	log.Info("Valid refresh token")
	return claims, nil
}

func HashRefreshToken(refreshTokenString string) string {
	hash := sha256.Sum256([]byte(refreshTokenString))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func GenerateFamilyID() uuid.UUID {
	return uuid.New()
}

func (m *Manager) GenerateJWKS() map[string]interface{} {
	return GenerateJWKS(m.PublicKey, m.kid)
}
