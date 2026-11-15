package federation

import "errors"

var (
	ErrInvalidProvider = errors.New("invalid oauth provider")
	ErrCodeExchange    = errors.New("failed to exchange code for token")
	ErrUserInfo        = errors.New("failed to fetch user info")
)

// UserInfo is the provider-agnostic identity every Provider returns. ID is the
// provider's stable subject and is what oauth_providers.provider_id stores.
type UserInfo struct {
	ID          string
	Email       string
	DisplayName string
	AvatarURL   string
	Provider    string
}

// Provider is the contract each OAuth provider implements. A single instance
// serves every request, so implementations must be safe for concurrent use.
// additionalData carries provider-specific extras posted by the client: Apple
// sends the user's name there, and only on the first authorization.
type Provider interface {
	GetAuthURL(state string) string
	ExchangeCode(code string, additionalData string) (UserInfo, error)
}
