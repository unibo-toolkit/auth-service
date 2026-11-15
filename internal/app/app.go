package app

import (
	"context"
	"log/slog"
	"time"

	httpapp "github.com/unibo-toolkit/auth-service/internal/app/http"
	"github.com/unibo-toolkit/auth-service/internal/config"
	"github.com/unibo-toolkit/auth-service/internal/storage"
)

// App aggregates the service's sub-applications. Each one owns its transport and
// is started and stopped through App.
type App struct {
	HttpApp *httpapp.App
}

// New constructs the application and wires its HTTP dependencies.
func New(log *slog.Logger, st *storage.Storage, cfg *config.Config) *App {
	httpApp := httpapp.NewApp(log, st, cfg)

	return &App{
		HttpApp: httpApp,
	}
}

// Shutdown stops every sub-application within a ten-second budget.
func (a *App) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.HttpApp.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}
