//go:build integration

package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/observability"
	"github.com/LCGant/role-pdp/internal/store/cache"
	"github.com/LCGant/role-pdp/internal/store/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const adminToken = "integration-secret"
const internalToken = "integration-internal-secret"

func TestIntegrationDecisionAllowAndTenantDeny(t *testing.T) {
	srv, cleanup := startIntegrationServer(t)
	defer cleanup()

	allowBody := `{"subject":{"user_id":"user-admin","tenant_id":"tenant-1","aal":2},"action":"orders:read","resource":{"type":"orders","id":"1","tenant_id":"tenant-1"},"context":{"ip":"127.0.0.1"}}`
	resp, body := postJSON(t, srv.URL+"/v1/decision", allowBody, map[string]string{"X-Internal-Token": internalToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var decision authz.DecisionResponse
	if err := json.Unmarshal(body, &decision); err != nil {
		t.Fatalf("unmarshal decision: %v", err)
	}
	if !decision.Allow {
		t.Fatalf("expected allow, got deny: %+v", decision)
	}

	tenantMismatch := `{"subject":{"user_id":"user-admin","tenant_id":"tenant-1"},"action":"orders:read","resource":{"type":"orders","id":"1","tenant_id":"tenant-2"},"context":{"ip":"127.0.0.1"}}`
	resp, body = postJSON(t, srv.URL+"/v1/decision", tenantMismatch, map[string]string{"X-Internal-Token": internalToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &decision); err != nil {
		t.Fatalf("unmarshal decision: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expected deny for tenant mismatch")
	}
}

func TestIntegrationDecisionUnknownField(t *testing.T) {
	srv, cleanup := startIntegrationServer(t)
	defer cleanup()

	body := `{"subject":{"user_id":"user-admin","tenant_id":"tenant-1"},"action":"orders:read","resource":{"type":"orders","tenant_id":"tenant-1"},"bad":true}`
	resp, _ := postJSON(t, srv.URL+"/v1/decision", body, map[string]string{"X-Internal-Token": internalToken})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIntegrationAdminAuth(t *testing.T) {
	srv, cleanup := startIntegrationServer(t)
	defer cleanup()

	body := `{"name":"new-role"}`
	resp, _ := postJSON(t, srv.URL+"/v1/admin/roles", body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	headers := map[string]string{"X-Admin-Token": adminToken}
	resp, _ = postJSON(t, srv.URL+"/v1/admin/roles", body, headers)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 with token, got %d", resp.StatusCode)
	}
}

func startIntegrationServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	dbURL := os.Getenv("TEST_DB_URL")
	if dbURL == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	if err := applyMigration(ctx, db); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	if err := seedRBAC(ctx, db); err != nil {
		t.Fatalf("seed rbac: %v", err)
	}

	store, err := postgres.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	logger := slogDiscard()
	cached := cache.New(store, 0)
	auditor := &observability.AuditLogger{Sink: cached, Logger: logger}
	engine := authz.NewEngine(cached, auditor, logger, &authz.Options{
		EnableOwnershipCheck: true,
	})
	router := NewRouter(RouterParams{
		Logger:        logger,
		Engine:        engine,
		EnableMetrics: false,
		RateLimiter:   NewRateLimiter(120, 30),
		Readiness:     ReadinessHandler{DB: store, Cache: cached},
		AdminToken:    adminToken,
		InternalToken: internalToken,
		AdminStore:    AdminAdapter{Inner: store},
	})

	srv := httptest.NewServer(router)
	return srv, func() {
		srv.Close()
		store.Close()
		db.Close()
		cancel()
	}
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func postJSON(t *testing.T, url string, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func applyMigration(ctx context.Context, db *sql.DB) error {
	path := filepath.Join("..", "..", "..", "db", "migrations", "0001_init.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(body))
	return err
}

func seedRBAC(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`DELETE FROM policy_audit_log`,
		`DELETE FROM user_roles`,
		`DELETE FROM role_permissions`,
		`DELETE FROM permissions`,
		`DELETE FROM roles`,
		`INSERT INTO roles (tenant_id, name) VALUES ('tenant-1','admin') ON CONFLICT DO NOTHING`,
		`INSERT INTO permissions (name) VALUES ('orders:read') ON CONFLICT DO NOTHING`,
		`INSERT INTO role_permissions (role_id, permission_id) SELECT r.id, p.id FROM roles r, permissions p WHERE r.name='admin' AND p.name='orders:read' ON CONFLICT DO NOTHING`,
		`INSERT INTO user_roles (user_id, tenant_id, role_id) SELECT 'user-admin', r.tenant_id, r.id FROM roles r WHERE r.name='admin' ON CONFLICT DO NOTHING`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
