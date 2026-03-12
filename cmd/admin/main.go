package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/LCGant/role-pdp/internal/store/postgres"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: admin <command> [flags]\ncommands: create-role, create-perm, grant-perm, assign-role")
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	dbURL := envOr("PDP_DB_URL", envOr("DATABASE_URL", ""))
	if dbURL == "" {
		fmt.Println("PDP_DB_URL or DATABASE_URL is required")
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := postgres.New(ctx, dbURL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	switch cmd {
	case "create-role":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		tenant := fs.String("tenant", "", "tenant id (optional for global)")
		name := fs.String("name", "", "role name")
		fs.Parse(args)
		if *name == "" {
			logger.Error("name is required")
			os.Exit(1)
		}
		if err := store.CreateRole(ctx, *tenant, *name); err != nil {
			logger.Error("create role failed", "error", err)
			os.Exit(1)
		}
	case "create-perm":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		name := fs.String("name", "", "permission name")
		fs.Parse(args)
		if *name == "" {
			logger.Error("name is required")
			os.Exit(1)
		}
		if err := store.CreatePermission(ctx, *name); err != nil {
			logger.Error("create perm failed", "error", err)
			os.Exit(1)
		}
	case "grant-perm":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		role := fs.String("role", "", "role name")
		tenant := fs.String("tenant", "", "tenant id")
		perm := fs.String("perm", "", "permission name")
		fs.Parse(args)
		if *role == "" || *perm == "" {
			logger.Error("role and perm are required")
			os.Exit(1)
		}
		if err := store.GrantPermission(ctx, *role, *tenant, *perm); err != nil {
			logger.Error("grant perm failed", "error", err)
			os.Exit(1)
		}
	case "assign-role":
		fs := flag.NewFlagSet(cmd, flag.ExitOnError)
		user := fs.String("user", "", "user id")
		tenant := fs.String("tenant", "", "tenant id")
		role := fs.String("role", "", "role name")
		fs.Parse(args)
		if *user == "" || *tenant == "" || *role == "" {
			logger.Error("user, tenant, role are required")
			os.Exit(1)
		}
		if err := store.AssignUserRole(ctx, *user, *tenant, *role); err != nil {
			logger.Error("assign role failed", "error", err)
			os.Exit(1)
		}
	default:
		logger.Error("unknown command", "cmd", cmd)
		os.Exit(1)
	}
	logger.Info("done", "cmd", cmd)
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
