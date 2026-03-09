package httpapp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	httpServer "github.com/unibo-toolkit/auth-service/internal/http/auth"
	"github.com/unibo-toolkit/auth-service/internal/storage"
)

type App struct {
	httpServer *httpServer.Server
	log        *slog.Logger
	storage    *storage.Storage
}

func NewApp(log *slog.Logger, st *storage.Storage) *App {
	server := httpServer.New(log, st)
	server.RegisterRoutes()

	return &App{
		httpServer: server,
		log:        log,
		storage:    st,
	}
}

func (a *App) Run(addr string) {
	const op = "app.http.Run"
	log := a.log.With("op", op)

	log.Info("Starting HTTP server")

	go func() {
		a.httpServer.Addr = addr
		err := a.httpServer.ListenAndServe()

		if err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}
	}()

	log.Info("HTTP server is running", slog.String("addr", addr))
}

func (a *App) Shutdown(ctx context.Context) error {
	const op = "app.http.Shutdown"
	log := a.log.With("op", op)
	log.Info("Shutting down HTTP server")

	a.httpServer.ShutdownService()

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return a.httpServer.Shutdown(shutdownCtx)
}
