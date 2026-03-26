package auth

import "errors"

var (
	ErrInvalidCode         = errors.New("invalid oauth2 code")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenReused         = errors.New("token already used")
)
