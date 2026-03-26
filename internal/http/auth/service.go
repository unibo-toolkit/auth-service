package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/unibo-toolkit/auth-service/internal/config"
	"github.com/unibo-toolkit/auth-service/internal/jwt"
	"github.com/unibo-toolkit/auth-service/internal/oauth"
	"github.com/unibo-toolkit/auth-service/internal/storage"
	"github.com/unibo-toolkit/auth-service/internal/storage/db"
)

type Service struct {
	log             *slog.Logger
	storage         *storage.Storage
	jwtManager      *jwt.Manager
	oauthManager    *oauth.Manager
	refreshTokenTTL time.Duration
	accessTokenTTL  time.Duration
}

type AuthTokens struct {
	AccessToken  string
	RefreshToken string
}

func NewHttpService(log *slog.Logger, st *storage.Storage) *Service {
	cfg := config.MustLoad()

	jwtManager := jwt.MustNewJwtManager(log, cfg)

	oauthMgr := oauth.NewManager()

	if cfg.OAuth.GoogleClientID != "" {
		googleProvider := oauth.NewGoogleProvider(
			cfg.OAuth.GoogleClientID,
			cfg.OAuth.GoogleClientSecret,
			cfg.OAuth.GoogleRedirectURL,
		)
		oauthMgr.RegisterProvider("google", googleProvider)
	}

	if cfg.OAuth.AppleClientID != "" {
		appleProvider, err := oauth.NewAppleProvider(
			cfg.OAuth.AppleClientID,
			cfg.OAuth.AppleTeamID,
			cfg.OAuth.AppleKeyID,
			cfg.OAuth.ApplePrivateKey,
			cfg.OAuth.AppleRedirectURL,
		)
		if err != nil {
			log.Error("Failed to create Apple OAuth provider", "error", err)
		} else {
			oauthMgr.RegisterProvider("apple", appleProvider)
		}
	}

	return &Service{
		log:             log,
		storage:         st,
		jwtManager:      jwtManager,
		oauthManager:    oauthMgr,
		refreshTokenTTL: time.Duration(cfg.JWT.RefreshTokenTTL) * time.Second,
		accessTokenTTL:  time.Duration(cfg.JWT.AccessTokenTTL) * time.Second,
	}
}

func (s *Service) HandleOAuthCallback(
	ctx context.Context,
	provider string,
	code string,
	ipAddress string,
	userAgent string,
	deviceName string,
	additionalData string,
) (*AuthTokens, error) {
	log := s.log.With("op", "service.HandleOAuthCallback", "provider", provider)

	userInfo, err := s.oauthManager.ExchangeCode(provider, code, additionalData)
	if err != nil {
		log.Error("Failed to exchange code", "error", err)
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	var user *db.User
	existingUser, err := s.storage.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		user, err = s.createUser(ctx, userInfo)
		if err != nil {
			log.Error("Failed to create user", "error", err)
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
		if err := s.ensureOAuthProvider(ctx, user.ID, provider, userInfo.ID, userInfo.Email); err != nil {
			log.Error("Failed to ensure oauth provider", "error", err)
			return nil, fmt.Errorf("failed to ensure oauth provider: %w", err)
		}
	} else {
		user = &existingUser
		if err := s.ensureOAuthProvider(ctx, user.ID, provider, userInfo.ID, userInfo.Email); err != nil {
			log.Error("Failed to ensure oauth provider", "error", err)
			return nil, fmt.Errorf("failed to ensure oauth provider: %w", err)
		}
	}

	roles, err := s.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		log.Error("Failed to get user roles", "error", err)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	if err := s.storage.UpdateLastLogin(ctx, user.ID); err != nil {
		log.Error("Failed to update last login", "error", err)
	}

	tokens, err := s.createTokens(ctx, user.ID, user.Email, roleNames, ipAddress, userAgent, deviceName)
	if err != nil {
		log.Error("Failed to create tokens", "error", err)
		return nil, fmt.Errorf("failed to create tokens: %w", err)
	}

	if err := s.logLoginAttempt(ctx, user.ID, provider, ipAddress, userAgent, true, ""); err != nil {
		log.Error("Failed to log login attempt", "error", err)
	}

	log.Info("OAuth callback successful", "user_id", user.ID)
	return tokens, nil
}

func (s *Service) createUser(ctx context.Context, userInfo oauth.UserInfo) (*db.User, error) {
	log := s.log.With("op", "service.createUser", "email", userInfo.Email)

	user, err := s.storage.CreateUser(ctx, db.CreateUserParams{
		Email: userInfo.Email,
		DisplayName: pgtype.Text{
			String: userInfo.DisplayName,
			Valid:  userInfo.DisplayName != "",
		},
		AvatarUrl: pgtype.Text{
			String: userInfo.AvatarURL,
			Valid:  userInfo.AvatarURL != "",
		},
	})
	if err != nil {
		return nil, err
	}

	defaultRole, err := s.storage.GetRoleByName(ctx, "user")
	if err != nil {
		log.Error("Failed to get default role", "error", err)
		return nil, fmt.Errorf("failed to get default role: %w", err)
	}

	if err := s.storage.GrantRole(ctx, db.GrantRoleParams{
		UserID:    user.ID,
		RoleID:    defaultRole.ID,
		GrantedBy: pgtype.UUID{},
	}); err != nil {
		log.Error("Failed to add default role", "error", err)
		return nil, fmt.Errorf("failed to add default role: %w", err)
	}

	log.Info("User created successfully", "user_id", user.ID)
	return &user, nil
}

func (s *Service) ensureOAuthProvider(ctx context.Context, userID uuid.UUID, provider, providerUserID, email string) error {
	_, err := s.storage.GetOAuthProvider(ctx, db.GetOAuthProviderParams{
		Provider:   provider,
		ProviderID: providerUserID,
	})
	if err == nil {
		return nil
	}

	_, err = s.storage.CreateOAuthProvider(ctx, db.CreateOAuthProviderParams{
		UserID:     userID,
		Provider:   provider,
		ProviderID: providerUserID,
		Email:      pgtype.Text{String: email, Valid: email != ""},
	})
	return err
}

func (s *Service) createTokens(
	ctx context.Context,
	userID uuid.UUID,
	email string,
	roles []string,
	ipAddress string,
	userAgent string,
	deviceName string,
) (*AuthTokens, error) {
	log := s.log.With("op", "service.createTokens", "user_id", userID)

	accessToken, err := s.jwtManager.GenerateAccessToken(userID, email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	familyID := jwt.GenerateFamilyID()
	refreshToken, err := s.jwtManager.GenerateRefreshToken(userID, familyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	tokenHash := jwt.HashRefreshToken(refreshToken)

	var ip *netip.Addr
	if ipAddress != "" {
		if addr, err := netip.ParseAddr(ipAddress); err == nil {
			ip = &addr
		}
	}

	_, err = s.storage.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:     userID,
		TokenHash:  tokenHash,
		FamilyID:   familyID,
		ParentID:   pgtype.UUID{},
		IpAddress:  ip,
		UserAgent:  pgtype.Text{String: userAgent, Valid: userAgent != ""},
		DeviceName: pgtype.Text{String: deviceName, Valid: deviceName != ""},
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(s.refreshTokenTTL), Valid: true},
	})
	if err != nil {
		log.Error("Failed to store refresh token", "error", err)
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	log.Info("Tokens created successfully")
	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) RefreshTokens(
	ctx context.Context,
	refreshToken string,
	ipAddress string,
	userAgent string,
	deviceName string,
) (*AuthTokens, error) {
	log := s.log.With("op", "service.RefreshTokens")

	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		log.Error("Invalid refresh token", "error", err)
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	tokenHash := jwt.HashRefreshToken(refreshToken)
	storedToken, err := s.storage.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		log.Error("Refresh token not found", "error", err)
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}

	if storedToken.RevokedAt.Valid {
		err = s.revokeTokenFamily(ctx, storedToken.FamilyID)
		if err != nil {
			log.Error("Failed to revoke token family", "error", err)
			return nil, fmt.Errorf("failed to revoke token family: %w", err)
		}
		log.Warn("Refresh token has been revoked (possible replay attack)", "family_id", storedToken.FamilyID)
		return nil, ErrTokenReused
	}

	if storedToken.UsedAt.Valid {
		err = s.revokeTokenFamily(ctx, storedToken.FamilyID)
		if err != nil {
			log.Error("Failed to revoke token family", "error", err)
			return nil, fmt.Errorf("failed to revoke token family: %w", err)
		}
		log.Warn("Refresh token already used (possible replay attack)", "family_id", storedToken.FamilyID)
		return nil, ErrTokenReused
	}

	now := time.Now()
	if storedToken.ExpiresAt.Time.Before(now) {
		log.Error("Refresh token expired")
		return nil, fmt.Errorf("refresh token expired")
	}

	if err := s.storage.UpdateTokenUsedAt(ctx, storedToken.ID); err != nil {
		log.Error("Failed to mark token as used", "error", err)
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	roles, err := s.storage.GetUserRoles(ctx, claims.UserID)
	if err != nil {
		log.Error("Failed to get user roles", "error", err)
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	user, err := s.storage.GetUserByID(ctx, claims.UserID)
	if err != nil {
		log.Error("Failed to get user", "error", err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	accessToken, err := s.jwtManager.GenerateAccessToken(claims.UserID, user.Email, roleNames)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(claims.UserID, storedToken.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	newTokenHash := jwt.HashRefreshToken(newRefreshToken)

	var ip *netip.Addr
	if ipAddress != "" {
		if addr, err := netip.ParseAddr(ipAddress); err == nil {
			ip = &addr
		}
	}

	_, err = s.storage.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:     claims.UserID,
		TokenHash:  newTokenHash,
		FamilyID:   storedToken.FamilyID,
		ParentID:   pgtype.UUID{Bytes: storedToken.ID, Valid: true},
		IpAddress:  ip,
		UserAgent:  pgtype.Text{String: userAgent, Valid: userAgent != ""},
		DeviceName: pgtype.Text{String: deviceName, Valid: deviceName != ""},
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(s.refreshTokenTTL), Valid: true},
	})
	if err != nil {
		log.Error("Failed to store new refresh token", "error", err)
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	log.Info("Tokens refreshed successfully", "user_id", claims.UserID)
	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *Service) revokeTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	return s.storage.RevokeTokenFamily(ctx, familyID)
}

func (s *Service) logLoginAttempt(
	ctx context.Context,
	userID uuid.UUID,
	provider string,
	ipAddress string,
	userAgent string,
	success bool,
	failureReason string,
) error {
	var ip *netip.Addr
	if ipAddress != "" {
		if addr, err := netip.ParseAddr(ipAddress); err == nil {
			ip = &addr
		}
	}

	_, err := s.storage.CreateLoginHistory(ctx, db.CreateLoginHistoryParams{
		UserID:        userID,
		OauthProvider: pgtype.Text{String: provider, Valid: provider != ""},
		IpAddress:     ip,
		UserAgent:     pgtype.Text{String: userAgent, Valid: userAgent != ""},
		Success:       success,
		FailureReason: pgtype.Text{String: failureReason, Valid: failureReason != ""},
	})
	return err
}
