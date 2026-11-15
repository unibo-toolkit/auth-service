package auth

import "github.com/unibo-toolkit/auth-service/internal/storage"

// Service temporarily holds the profile API dependencies. OIDC login business
// logic is introduced by the later implementation stages.
type Service struct {
	storage *storage.Storage
}

// NewHttpService returns a profile service backed by st.
func NewHttpService(st *storage.Storage) *Service {
	return &Service{storage: st}
}
