package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/unibo-toolkit/auth-service/internal/config"
	"github.com/unibo-toolkit/auth-service/internal/jwt"
	"github.com/unibo-toolkit/auth-service/internal/storage"
	"github.com/unibo-toolkit/auth-service/internal/storage/db"
)

type Server struct {
	log     *slog.Logger
	service *Service
	*gin.Engine
	*http.Server

	stateStore   map[string]time.Time
	stateStoreMu sync.RWMutex
}

var cfg = config.MustLoad()

func New(log *slog.Logger, st *storage.Storage) *Server {
	if cfg.Http.Environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	engine := gin.New()
	engine.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/api/v1/auth/health"},
	}))
	engine.Use(gin.Recovery())
	err := engine.SetTrustedProxies(nil)
	if err != nil {
		log.Error("Failed to set trusted proxies", "error", err)
		panic(err)
	}

	headerCfg := config.MustLoad().Http
	engine.TrustedPlatform = headerCfg.IpHeader

	server := &http.Server{Handler: engine.Handler()}

	service := NewHttpService(log, st)

	srv := &Server{
		log:        log,
		service:    service,
		Engine:     engine,
		Server:     server,
		stateStore: make(map[string]time.Time),
	}

	go srv.cleanupExpiredStates()

	return srv
}

func (s *Server) RegisterRoutes() {
	v1 := s.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.GET("/health", s.healthHandler)
			auth.GET("/.well-known/jwks.json", s.jwksHandler)

			auth.GET("/:provider", s.handleOAuthStart)
			auth.GET("/:provider/callback", s.handleOAuthCallback)
			auth.POST("/:provider/callback", s.handleOAuthCallback) // used by apple
			auth.POST("/exchange", s.handleExchangeCode)
			auth.POST("/refresh", s.handleRefresh)
			auth.POST("/logout", s.handleLogout)
			auth.POST("/logout-all", s.handleLogoutAll)
		}

		users := v1.Group("/users/me")
		users.Use(s.requireAuth)
		{
			users.GET("/", s.handleGetProfile)
			users.PATCH("/", s.handleUpdateProfile)
			users.DELETE("/", s.handleDeleteAccount)
			users.GET("/sessions", s.handleGetSessions)
			users.DELETE("/sessions/:sessionID", s.handleRevokeSession)
			users.GET("/login-history", s.handleGetLoginHistory)
		}
	}

	s.NoRoute(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNotFound)
	})
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) jwksHandler(c *gin.Context) {
	jwks := s.service.jwtManager.GenerateJWKS()
	c.JSON(http.StatusOK, jwks)
}

func (s *Server) handleOAuthStart(c *gin.Context) {
	provider := c.Param("provider")

	state, err := s.generateAndStoreState()
	if err != nil {
		s.log.Error("failed to generate state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	authURL, err := s.service.oauthManager.GetAuthURL(provider, state)
	if err != nil {
		s.log.Error("failed to get auth URL", "error", err, "provider", provider)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func (s *Server) handleOAuthCallback(c *gin.Context) {
	provider := c.Param("provider")

	state := c.Request.FormValue("state")
	if !s.validateAndRemoveState(state) {
		s.log.Warn("invalid state parameter")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}

	code := c.Request.FormValue("code")
	if code == "" {
		s.log.Warn("missing code parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	ipAddress := s.getIP(c)
	userAgent := c.Request.UserAgent()
	if userAgent == "" {
		userAgent = "unknown"
	}
	deviceName := c.Request.FormValue("device_name")
	userData := c.Request.FormValue("user")

	tokens, err := s.service.HandleOAuthCallback(
		c.Request.Context(),
		provider,
		code,
		ipAddress,
		userAgent,
		deviceName,
		userData,
	)
	if err != nil {
		s.log.Error("oauth callback failed", "error", err, "provider", provider)
		if errors.Is(err, ErrInvalidCode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "auth failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (s *Server) handleExchangeCode(c *gin.Context) {
	var req struct {
		Provider   string `json:"provider" binding:"required"`
		Code       string `json:"code" binding:"required"`
		State      string `json:"state"`
		User       string `json:"user"`
		DeviceName string `json:"device_name"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
		return
	}

	if req.State != "" && !s.validateAndRemoveState(req.State) {
		s.log.Warn("invalid state parameter")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}

	ipAddress := s.getIP(c)
	userAgent := c.Request.UserAgent()
	if userAgent == "" {
		userAgent = "unknown"
	}

	tokens, err := s.service.HandleOAuthCallback(
		c.Request.Context(),
		req.Provider,
		req.Code,
		ipAddress,
		userAgent,
		req.DeviceName,
		req.User,
	)
	if err != nil {
		s.log.Error("oauth exchange failed", "error", err, "provider", req.Provider)
		if errors.Is(err, ErrInvalidCode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "auth failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (s *Server) handleRefresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh token"})
		return
	}

	ipAddress := s.getIP(c) // TODO verify istio compatibility
	userAgent := c.Request.UserAgent()
	if userAgent == "" {
		userAgent = "unknown"
	}
	deviceName := c.Query("device_name")

	tokens, err := s.service.RefreshTokens(
		c.Request.Context(),
		req.RefreshToken,
		ipAddress,
		userAgent,
		deviceName,
	)
	if err != nil {
		s.log.Error("refresh failed", "error", err)
		if errors.Is(err, ErrInvalidRefreshToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}
		if errors.Is(err, ErrTokenReused) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token already used"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (s *Server) handleLogout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh token"})
		return
	}

	tokenHash := hashRefreshToken(req.RefreshToken)
	storedToken, err := s.service.storage.GetRefreshTokenByHash(c.Request.Context(), tokenHash)
	if err == nil {
		s.service.storage.RevokeRefreshToken(c.Request.Context(), db.RevokeRefreshTokenParams{
			ID:            storedToken.ID,
			RevokedReason: pgtype.Text{String: "user_logout", Valid: true},
		})
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) handleLogoutAll(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing refresh token"})
		return
	}

	claims, err := s.service.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if err := s.service.storage.RevokeAllUserTokens(c.Request.Context(), claims.UserID); err != nil {
		s.log.Error("logout all failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) requireAuth(c *gin.Context) {
	var userID uuid.UUID
	var email string
	var roles []string

	if cfg.Http.Environment == "prod" {
		userIDStr := c.GetHeader("X-User-Id")
		rolesStr := c.GetHeader("X-Roles")

		if userIDStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		parsedID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
			return
		}

		userID = parsedID
		email = c.GetHeader("X-Email")
		if rolesStr != "" {
			roles = parseRoles(rolesStr)
		}
	} else {
		token := c.GetHeader("Authorization")
		if token == "" || len(token) < 8 || token[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		claims, err := s.service.jwtManager.ValidateAccessToken(token[7:])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		userID = claims.UserID
		email = claims.Email
		roles = claims.Roles
	}

	c.Set("user_id", userID)
	c.Set("email", email)
	c.Set("roles", roles)

	c.Next()
}

func (s *Server) handleGetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	roles, _ := c.Get("roles")

	user, err := s.service.storage.GetUserByID(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		s.log.Error("failed to get user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           user.ID,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarUrl,
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
		"last_login":   user.LastLogin,
		"roles":        roles,
	})
}

func (s *Server) handleUpdateProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var req struct {
		DisplayName string `json:"display_name" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	trimmed := strings.TrimSpace(req.DisplayName)
	if trimmed == "" || len(trimmed) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name must be 1-255 characters"})
		return
	}

	user, err := s.service.storage.UpdateUser(c.Request.Context(), db.UpdateUserParams{
		ID:          userID.(uuid.UUID),
		DisplayName: pgtype.Text{String: trimmed, Valid: true},
	})
	if err != nil {
		s.log.Error("failed to update user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	roles, _ := c.Get("roles")

	c.JSON(http.StatusOK, gin.H{
		"id":           user.ID,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarUrl,
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
		"last_login":   user.LastLogin,
		"roles":        roles,
	})
}

func (s *Server) handleDeleteAccount(c *gin.Context) {
	userID, _ := c.Get("user_id")

	if err := s.service.storage.DeleteAccount(c.Request.Context(), userID.(uuid.UUID)); err != nil {
		s.log.Error("failed to delete account", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Account deleted successfully",
	})
}

func (s *Server) handleGetSessions(c *gin.Context) {
	userID, _ := c.Get("user_id")

	sessions, err := s.service.storage.GetActiveSessionFamilies(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		s.log.Error("failed to get sessions", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get sessions"})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

func (s *Server) handleRevokeSession(c *gin.Context) {
	userID, _ := c.Get("user_id")
	familyIDStr := c.Param("sessionID")

	familyID, err := uuid.Parse(familyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}

	tokens, err := s.service.storage.GetActiveSessionsByUserID(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get sessions"})
		return
	}

	found := false
	for _, token := range tokens {
		if token.FamilyID == familyID {
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	if err := s.service.storage.RevokeTokenFamily(c.Request.Context(), familyID); err != nil {
		s.log.Error("failed to revoke session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) handleGetLoginHistory(c *gin.Context) {
	userID, _ := c.Get("user_id")

	history, err := s.service.storage.GetLoginHistory(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		s.log.Error("failed to get login history", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get login history"})
		return
	}

	c.JSON(http.StatusOK, history)
}

func (s *Server) generateAndStoreState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := hex.EncodeToString(b)

	s.stateStoreMu.Lock()
	defer s.stateStoreMu.Unlock()
	s.stateStore[state] = time.Now().Add(10 * time.Minute)

	return state, nil
}

func (s *Server) validateAndRemoveState(state string) bool {
	s.stateStoreMu.Lock()
	defer s.stateStoreMu.Unlock()

	expiry, exists := s.stateStore[state]
	if !exists {
		return false
	}

	delete(s.stateStore, state)

	return time.Now().Before(expiry)
}

func (s *Server) cleanupExpiredStates() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.stateStoreMu.Lock()
		now := time.Now()
		for state, expiry := range s.stateStore {
			if now.After(expiry) {
				delete(s.stateStore, state)
			}
		}
		s.stateStoreMu.Unlock()
	}
}

func (s *Server) getIP(c *gin.Context) string {
	fullHeader := c.ClientIP()
	headerParts := strings.Split(fullHeader, ",")
	return headerParts[0]
}

func (s *Server) ShutdownService() {
	s.log.Info("Shutting down service")
}

func parseRoles(header string) []string {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return []string{header}
	}
	var roles []string
	if err := json.Unmarshal(decoded, &roles); err != nil {
		return []string{string(decoded)}
	}
	return roles
}

func hashRefreshToken(token string) string {
	return jwt.HashRefreshToken(token)
}
