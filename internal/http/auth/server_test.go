package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unibo-toolkit/auth-service/internal/config"
)

func TestStageZeroRoutes(t *testing.T) {
	privatePEM := testPrivatePEM(t)
	cfg := &config.Config{
		Http: config.HttpConfig{Environment: "test"},
		OIDC: config.OIDCConfig{Issuer: "https://issuer.example", APIAudience: "api", SigningKeys: []string{privatePEM}},
	}
	server := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, cfg)
	server.RegisterRoutes()

	removedRoutes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/auth/google"},
		{method: http.MethodPost, path: "/api/v1/auth/refresh"},
		{method: http.MethodPost, path: "/api/v1/auth/logout"},
	}
	for _, route := range removedRoutes {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("%s %s returned %d, want 404", route.method, route.path, response.Code)
		}
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("JWKS returned %d, want 200", response.Code)
	}
}

func testPrivatePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
