package authz

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/observability"
	"github.com/LCGant/role-pdp/internal/store"
)

func BenchmarkDecide(b *testing.B) {
	st := &benchStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, benchmarkLogger(), &Options{
		EnableOwnershipCheck: true,
		DecisionCacheTTL:     time.Minute,
	})
	req := DecisionRequest{
		Subject:  Subject{UserID: "u1", TenantID: "t1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", TenantID: "t1"},
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Decide(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type benchStore struct {
	perms []string
}

func (s *benchStore) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	return s.perms, nil
}

func (s *benchStore) LogDecision(ctx context.Context, entry store.AuditLogEntry) error {
	return nil
}

func (s *benchStore) Close() error { return nil }
