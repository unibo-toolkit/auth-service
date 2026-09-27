package auth

import "errors"

// Sentinel errors of the auth layer. The handlers map ErrInvalidCode to 400,
// ErrInvalidRefreshToken and ErrTokenReused to 401.
var (
	ErrInvalidCode         = errors.New("invalid oauth2 code")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenReused         = errors.New("token already used")
)
