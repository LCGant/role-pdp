package store

import (
	"context"
	"time"
)

// PolicyStore defines the persistence contract used by the authorization engine.
type PolicyStore interface {
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error)
	LogDecision(ctx context.Context, entry AuditLogEntry) error
	Close() error
}

type AuditLogEntry struct {
	SubjectUserID string
	TenantID      string
	Action        string
	ResourceType  string
	ResourceID    string
	Allow         bool
	Reason        string
	IP            string
	CreatedAt     time.Time
}
