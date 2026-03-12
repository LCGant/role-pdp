package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/LCGant/role-pdp/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

func New(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("empty postgres dsn")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	const query = `
SELECT DISTINCT p.name
FROM user_roles ur
JOIN roles r ON ur.role_id = r.id
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = $1
  AND ur.tenant_id = $2
  AND (r.tenant_id = $2 OR r.tenant_id IS NULL)
`
	rows, err := s.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		perms = append(perms, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return perms, nil
}

func (s *Store) LogDecision(ctx context.Context, entry store.AuditLogEntry) error {
	const stmt = `
INSERT INTO policy_audit_log
	(subject_user_id, tenant_id, action, resource_type, resource_id, allow, reason, ip, created_at)
VALUES
	($1, $2, $3, $4, $5, $6, $7, $8, $9)
`
	createdAt := entry.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, stmt,
		entry.SubjectUserID,
		entry.TenantID,
		entry.Action,
		entry.ResourceType,
		toNullString(entry.ResourceID),
		entry.Allow,
		entry.Reason,
		entry.IP,
		createdAt,
	)
	return err
}

func toNullString(v string) sql.NullString {
	if strings.TrimSpace(v) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func (s *Store) PingContext(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("store not initialized")
	}
	return s.db.PingContext(ctx)
}
