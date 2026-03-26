package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata"

	"github.com/unibo-toolkit/auth-service/internal/app"
	"github.com/unibo-toolkit/auth-service/internal/config"
	"github.com/unibo-toolkit/auth-service/internal/storage"
)

func main() {
	log := setupLogger()
	cfg := config.MustLoad()

	log.Info("Starting auth service", slog.Int("port", int(cfg.Http.Port)), slog.String("environment", cfg.Http.Environment))

	st := storage.New(log)
	application := app.New(log, st)

	addr := fmt.Sprintf(":%d", cfg.Http.Port)
	application.HttpApp.Run(addr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("Received shutdown signal", slog.String("signal", sign.String()))

	if err := application.Shutdown(); err != nil {
		log.Error("Shutdown failed", slog.String("error", err.Error()))
	}
	st.Shutdown()

	log.Info("Auth service stopped")
}

func setupLogger() *slog.Logger {
	levelStr := os.Getenv("LOG_LEVEL")
	var level slog.Level
	switch levelStr {
	case "debug":
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
