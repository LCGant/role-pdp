package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/LCGant/role-pdp/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	if cfg.DBURL == "" {
		logger.Error("PDP_DB_URL (or DATABASE_URL) must be set for seeding")
		os.Exit(1)
	}

	body, err := os.ReadFile("db/seeds/rbac_sample.sql")
	if err != nil {
		logger.Error("failed to read seed file", "error", err)
		os.Exit(1)
	}

	db, err := sql.Open("pgx", cfg.DBURL)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		logger.Error("database ping failed", "error", err)
		os.Exit(1)
	}

	if _, err := db.ExecContext(ctx, string(body)); err != nil {
		logger.Error("failed to apply seeds", "error", err)
		os.Exit(1)
	}

	fmt.Println("seed data applied successfully")
}
