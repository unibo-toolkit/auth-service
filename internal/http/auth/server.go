package auth

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/unibo-toolkit/auth-service/internal/config"
	jwtservice "github.com/unibo-toolkit/auth-service/internal/jwt"
	"github.com/unibo-toolkit/auth-service/internal/storage"
	"github.com/unibo-toolkit/auth-service/internal/storage/db"
)

// Server exposes the HTTP endpoints implemented by the current development stage.
type Server struct {
	log      *slog.Logger
	service  *Service
	cfg      *config.Config
	ring     *jwtservice.KeyRing
	verifier *jwtservice.Verifier
	*gin.Engine
	*http.Server
}

// New creates an HTTP server and initializes its signing-key ring and verifier.
func New(log *slog.Logger, st *storage.Storage, cfg *config.Config) *Server {
	if cfg.Http.Environment == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	ring, err := jwtservice.NewKeyRing(cfg.OIDC.SigningKeys)
	if err != nil {
		log.Error("Failed to initialize signing keys", "error", err)
		panic(err)
	}

	engine := gin.New()
	engine.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/health"}}))
	engine.Use(gin.Recovery())
	if err := engine.SetTrustedProxies(nil); err != nil {
		log.Error("Failed to set trusted proxies", "error", err)
		panic(err)
	}
	engine.TrustedPlatform = cfg.Http.IpHeader

	return &Server{
		log:      log,
		service:  NewHttpService(st),
		cfg:      cfg,
		ring:     ring,
		verifier: jwtservice.NewVerifier(ring, cfg.OIDC.Issuer),
		Engine:   engine,
		Server: &http.Server{
			Handler:           engine.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

// RegisterRoutes attaches health, JWKS, and authenticated profile routes.
func (s *Server) RegisterRoutes() {
	s.GET("/health", s.healthHandler)
	s.GET("/.well-known/jwks.json", s.jwksHandler)

	users := s.Group("/api/v1/users/me")
	users.Use(s.requireAuth)
	users.GET("/", s.handleGetProfile)
	users.PATCH("/", s.handleUpdateProfile)
	users.DELETE("/", s.handleDeleteAccount)
	users.GET("/sessions", s.handleGetSessions)
	users.DELETE("/sessions/:sessionID", s.handleRevokeSession)
	users.GET("/login-history", s.handleGetLoginHistory)

	s.NoRoute(func(c *gin.Context) { c.AbortWithStatus(http.StatusNotFound) })
}

func (s *Server) healthHandler(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) }

func (s *Server) jwksHandler(c *gin.Context) { c.JSON(http.StatusOK, s.ring.JWKS()) }

// requireAuth resolves the caller from the Bearer access token and publishes
// user_id and roles into the gin context. The token is validated here in every
// environment: this service holds the signing keys, so it never has to trust
// identity headers set by the gateway.
func (s *Server) requireAuth(c *gin.Context) {
	authorization := c.GetHeader("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	claims, err := s.verifier.ParseAccess(strings.TrimPrefix(authorization, "Bearer "), s.cfg.OIDC.APIAudience)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
		return
	}

	c.Set("user_id", userID)
	c.Set("roles", claims.Roles)
	c.Next()
}

func (s *Server) handleGetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	roles, _ := c.Get("roles")
	user, err := s.service.storage.GetUserByID(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
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
	user, err := s.service.storage.UpdateUser(c.Request.Context(), db.UpdateUserParams{ID: userID.(uuid.UUID), DisplayName: pgtype.Text{String: trimmed, Valid: true}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}
	roles, _ := c.Get("roles")
	c.JSON(http.StatusOK, gin.H{
		"id":           user.ID,
		"email":        user.Email,
		"display_name": user.DisplayName, "avatar_url": user.AvatarUrl, "created_at": user.CreatedAt, "updated_at": user.UpdatedAt, "last_login": user.LastLogin, "roles": roles})
}

func (s *Server) handleDeleteAccount(c *gin.Context) {
	userID, _ := c.Get("user_id")
	if err := s.service.storage.DeleteAccount(c.Request.Context(), userID.(uuid.UUID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete account"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Account deleted successfully"})
}

func (s *Server) handleGetSessions(c *gin.Context) {
	userID, _ := c.Get("user_id")
	sessions, err := s.service.storage.GetActiveSessionFamilies(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get sessions"})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

func (s *Server) handleRevokeSession(c *gin.Context) {
	userID, _ := c.Get("user_id")
	familyID, err := uuid.Parse(c.Param("sessionID"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}
	tokens, err := s.service.storage.GetActiveSessionsByUserID(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get sessions"})
		return
	}
	for _, token := range tokens {
		if token.FamilyID == familyID {
			if err := s.service.storage.RevokeTokenFamily(c.Request.Context(), familyID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
}

func (s *Server) handleGetLoginHistory(c *gin.Context) {
	userID, _ := c.Get("user_id")
	history, err := s.service.storage.GetLoginHistory(c.Request.Context(), userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get login history"})
		return
	}
	c.JSON(http.StatusOK, history)
}

// ShutdownService stops background service work. The current implementation has
// no background workers and only records the shutdown event.
func (s *Server) ShutdownService() { s.log.Info("Shutting down service") }
