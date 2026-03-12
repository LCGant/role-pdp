package postgres

import (
	"context"
	"database/sql"
)

func (s *Store) CreateRole(ctx context.Context, tenantID, name string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO roles (tenant_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, tenantID, name)
	return err
}

func (s *Store) CreatePermission(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO permissions (name) VALUES ($1) ON CONFLICT DO NOTHING`, name)
	return err
}

func (s *Store) GrantPermission(ctx context.Context, roleName, tenantID, permName string) error {
	const q = `
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = $1 AND (r.tenant_id = $2 OR r.tenant_id IS NULL) AND p.name = $3
ON CONFLICT DO NOTHING`
	res, err := s.db.ExecContext(ctx, q, roleName, tenantID, permName)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		roleExists, err := s.roleExists(ctx, roleName, tenantID)
		if err != nil {
			return err
		}
		permExists, err := s.permissionExists(ctx, permName)
		if err != nil {
			return err
		}
		if !roleExists || !permExists {
			return sql.ErrNoRows
		}
		// Idempotent case: permission already granted.
		return nil
	}
	return nil
}

func (s *Store) AssignUserRole(ctx context.Context, userID, tenantID, roleName string) error {
	const q = `
INSERT INTO user_roles (user_id, tenant_id, role_id)
SELECT $1, $2, r.id FROM roles r WHERE r.name = $3 AND (r.tenant_id = $2 OR r.tenant_id IS NULL)
ON CONFLICT DO NOTHING`
	res, err := s.db.ExecContext(ctx, q, userID, tenantID, roleName)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		roleExists, err := s.roleExists(ctx, roleName, tenantID)
		if err != nil {
			return err
		}
		if !roleExists {
			return sql.ErrNoRows
		}
		// Idempotent case: role already assigned.
		return nil
	}
	return nil
}

func (s *Store) roleExists(ctx context.Context, roleName, tenantID string) (bool, error) {
	var exists bool
	const q = `SELECT EXISTS (
SELECT 1 FROM roles WHERE name = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
)`
	if err := s.db.QueryRowContext(ctx, q, roleName, tenantID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Store) permissionExists(ctx context.Context, permission string) (bool, error) {
	var exists bool
	const q = `SELECT EXISTS (SELECT 1 FROM permissions WHERE name = $1)`
	if err := s.db.QueryRowContext(ctx, q, permission).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
