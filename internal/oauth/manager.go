package oauth

import (
	"fmt"
)

type Manager struct {
	providers map[string]Provider
}

func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]Provider),
	}
}

func (m *Manager) RegisterProvider(name string, provider Provider) {
	m.providers[name] = provider
}

func (m *Manager) GetProvider(name string) (Provider, error) {
	provider, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidProvider, name)
	}
	return provider, nil
}

func (m *Manager) GetAuthURL(providerName, state string) (string, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	return provider.GetAuthURL(state), nil
}

func (m *Manager) ExchangeCode(providerName, code, additionalData string) (UserInfo, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return UserInfo{}, err
	}
	return provider.ExchangeCode(code, additionalData)
}
