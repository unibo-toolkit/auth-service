package app

import (
	"context"
	"log/slog"
	"time"

	httpapp "github.com/unibo-toolkit/auth-service/internal/app/http"
	"github.com/unibo-toolkit/auth-service/internal/storage"
)

type App struct {
	HttpApp *httpapp.App
}

func New(log *slog.Logger, st *storage.Storage) *App {
	httpApp := httpapp.NewApp(log, st)

	return &App{
		HttpApp: httpApp,
	}
}

func (a *App) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.HttpApp.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}
