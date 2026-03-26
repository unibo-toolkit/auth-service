package oauth

import "errors"

var (
	ErrInvalidProvider = errors.New("invalid oauth provider")
	ErrCodeExchange    = errors.New("failed to exchange code for token")
	ErrUserInfo        = errors.New("failed to fetch user info")
)

type UserInfo struct {
	ID          string
	Email       string
	DisplayName string
	AvatarURL   string
	Provider    string
}

type Provider interface {
	GetAuthURL(state string) string
	ExchangeCode(code string, additionalData string) (UserInfo, error)
}
