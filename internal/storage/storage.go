package storage

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/unibo-toolkit/auth-service/internal/config"
	"github.com/unibo-toolkit/auth-service/internal/storage/db"
)

type Storage struct {
	Shutdown func()
	pool     *pgxpool.Pool
	*db.Queries
}

func Config() *pgxpool.Config {
	cfg := config.MustLoad().DB
	databaseURL := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name)
	dbConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		log.Fatal("Failed to create a config, error: ", err)
	}

	dbConfig.MaxConns = cfg.MaxConns
	dbConfig.MinConns = cfg.MinConns
	dbConfig.MaxConnLifetime = time.Duration(cfg.MaxConnLifetime)
	dbConfig.MaxConnIdleTime = time.Duration(cfg.MaxConnIdleTime)
	dbConfig.HealthCheckPeriod = time.Minute
	dbConfig.ConnConfig.ConnectTimeout = time.Second * 5

	return dbConfig
}

func New(log *slog.Logger) *Storage {
	conn, err := pgxpool.NewWithConfig(context.Background(), Config())
	if err != nil {
		log.Error("Failed to create a connection", "error", err)
		panic(err)
	}

	err = conn.Ping(context.Background())
	if err != nil {
		log.Error("Failed to ping the database", "error", err)
		panic(err)
	}

	queries := db.New(conn)

	return &Storage{conn.Close, conn, queries}
}

func (s *Storage) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	qtx := s.Queries.WithTx(tx)

	if err := qtx.RevokeAllUserTokensForDeletion(ctx, userID); err != nil {
		return err
	}

	if err := qtx.DeleteUser(ctx, userID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
