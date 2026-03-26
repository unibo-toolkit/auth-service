package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Http  HttpConfig
	DB    DBConfig
	JWT   JWTConfig
	OAuth OAuthConfig
}

type HttpConfig struct {
	Port        uint16 `env:"HTTP_PORT" env-default:"8081"`
	IpHeader    string `env:"HTTP_IP_HEADER"`
	Environment string `env:"ENVIRONMENT" env-default:"dev"`
}

type DBConfig struct {
	Host            string `env:"DB_HOST" env-default:"localhost"`
	Port            string `env:"DB_PORT" env-default:"5432"`
	User            string `env:"DB_USER" env-default:"unibo_user"`
	Pass            string `env:"DB_PASS" env-default:"unibo_pass"`
	Name            string `env:"DB_NAME" env-default:"unibo_toolkit"`
	MaxConns        int32  `env:"DB_MAX_CONNS" env-default:"10"`
	MinConns        int32  `env:"DB_MIN_CONNS" env-default:"1"`
	MaxConnLifetime int64  `env:"DB_MAX_CONN_LIFETIME" env-default:"3600000000000"`
	MaxConnIdleTime int64  `env:"DB_MAX_CONN_IDLE_TIME" env-default:"1800000000000"`
}

type JWTConfig struct {
	PrivateKey      string `env:"JWT_PRIVATE_KEY" env-required:"true"`
	PublicKey       string `env:"JWT_PUBLIC_KEY" env-required:"true"`
	AccessTokenTTL  int64  `env:"ACCESS_TOKEN_TTL" env-default:"900"`
	RefreshTokenTTL int64  `env:"REFRESH_TOKEN_TTL" env-default:"2592000"`
	Issuer          string `env:"JWT_ISSUER" env-default:"uniplanner.it"`
	Audience        string `env:"JWT_AUDIENCE" env-default:"uniplanner.it"`
	Kid             string `env:"JWT_KID" env-default:"key-2026-01"`
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

func MustLoad() *Config {
	var cfg Config

	if err := cleanenv.ReadEnv(&cfg); err != nil {
		panic("Failed to read config: " + err.Error())
	}

	return &cfg
}
