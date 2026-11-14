package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

// Config is the whole service configuration. Every field comes from an
// environment variable; there is no config file.
type Config struct {
	Http    HttpConfig
	DB      DBConfig
	JWT     JWTConfig
	OIDC    OIDCConfig
	Session SessionConfig
	OAuth   OAuthConfig
}

// OIDCConfig holds the OpenID Connect configuration for the service.
// It is used to generate the discovery document and JWKS endpoint.
type OIDCConfig struct {
	Issuer         string        `env:"OIDC_ISSUER" env-required:"true"`
	UIBaseURL      string        `env:"OIDC_UI_BASE_URL" env-required:"true"`
	SigningKeys    []string      `env:"OIDC_SIGNING_KEYS" env-required:"true" env-separator:";;"`
	APIAudience    string        `env:"OIDC_API_AUDIENCE" env-default:"uniplanner-api"`
	AuthRequestTTL time.Duration `env:"OIDC_AUTH_REQUEST_TTL" env-default:"10m"`
	AuthCodeTTL    time.Duration `env:"OIDC_AUTH_CODE_TTL" env-default:"60s"`
}

// SessionConfig holds the session cookie name and TTLs. The absolute TTL is the
// maximum lifetime of a session, while the idle TTL is the maximum time between
// two requests before the session expires.
type SessionConfig struct {
	CookieName  string        `env:"SESSION_COOKIE_NAME" env-default:"__Host-uniplanner_sid"`
	AbsoluteTTL time.Duration `env:"SESSION_ABSOLUTE_TTL" env-default:"720h"`
	IdleTTL     time.Duration `env:"SESSION_IDLE_TTL" env-default:"336h"`
}

type HttpConfig struct {
	Port        uint16 `env:"HTTP_PORT" env-default:"8081"`
	IpHeader    string `env:"HTTP_IP_HEADER"`
	Environment string `env:"ENVIRONMENT" env-default:"dev"`
}

// DBConfig holds the pgx pool settings. MaxConnLifetime and MaxConnIdleTime are
// time.Duration values, so they are expressed in nanoseconds.
type DBConfig struct {
	Host            string        `env:"DB_HOST" env-default:"localhost"`
	Port            string        `env:"DB_PORT" env-default:"5432"`
	User            string        `env:"DB_USER" env-default:"unibo_user"`
	Pass            string        `env:"DB_PASS" env-default:"unibo_pass"`
	Name            string        `env:"DB_NAME" env-default:"unibo_toolkit"`
	MaxConns        int32         `env:"DB_MAX_CONNS" env-default:"10"`
	MinConns        int32         `env:"DB_MIN_CONNS" env-default:"1"`
	MaxConnLifetime time.Duration `env:"DB_MAX_CONN_LIFETIME" env-default:"3600000000000ns"`
	MaxConnIdleTime time.Duration `env:"DB_MAX_CONN_IDLE_TIME" env-default:"1800000000000ns"`
}

type JWTConfig struct {
	PrivateKey      string        `env:"JWT_PRIVATE_KEY" env-required:"true"`
	PublicKey       string        `env:"JWT_PUBLIC_KEY" env-required:"true"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	Issuer          string        `env:"JWT_ISSUER" env-default:"uniplanner.it"`
	Audience        string        `env:"JWT_AUDIENCE" env-default:"uniplanner.it"`
	Kid             string        `env:"JWT_KID" env-default:"key-2026-01"`
}

type OAuthConfig struct {
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL  string `env:"GOOGLE_REDIRECT_URL"`
	AppleClientID      string `env:"APPLE_CLIENT_ID"`
	AppleTeamID        string `env:"APPLE_TEAM_ID"`
	AppleKeyID         string `env:"APPLE_KEY_ID"`
	ApplePrivateKey    string `env:"APPLE_PRIVATE_KEY"`
	AppleRedirectURL   string `env:"APPLE_REDIRECT_URL"`
}

// MustLoad reads the configuration from the environment and panics when a
// required variable is missing. It is called during package initialization, so a
// missing JWT key pair stops the process before any request is served.
func MustLoad() *Config {
	var cfg Config

	if err := cleanenv.ReadEnv(&cfg); err != nil {
		panic("Failed to read config: " + err.Error())
	}

	return &cfg
}
