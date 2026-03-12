//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestStoreIntegration_GetUserPermissions(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer st.Close()

	seedTestData(t, ctx, st.db)

	perms, err := st.GetUserPermissions(ctx, "user-admin", "tenant-1")
	if err != nil {
		t.Fatalf("GetUserPermissions error: %v", err)
	}
	if len(perms) == 0 {
		t.Fatalf("expected permissions for user-admin")
	}
}

func seedTestData(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
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
			t.Fatalf("seed stmt failed: %v", err)
		}
	}
}
