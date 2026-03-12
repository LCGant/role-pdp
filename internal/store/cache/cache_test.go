package cache

import (
	"context"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/store"
)

type stubPolicyStore struct {
	calls int
}

func (s *stubPolicyStore) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	s.calls++
	return []string{"orders:read"}, nil
}

func (s *stubPolicyStore) LogDecision(ctx context.Context, entry store.AuditLogEntry) error {
	return nil
}

func (s *stubPolicyStore) Close() error {
	return nil
}

func TestPermissionCacheCapsEntries(t *testing.T) {
	inner := &stubPolicyStore{}
	cache := New(inner, time.Minute)
	cache.maxEntries = 2

	_, _ = cache.GetUserPermissions(context.Background(), "u1", "t1")
	time.Sleep(2 * time.Millisecond)
	_, _ = cache.GetUserPermissions(context.Background(), "u2", "t1")
	time.Sleep(2 * time.Millisecond)
	_, _ = cache.GetUserPermissions(context.Background(), "u3", "t1")

	if got := len(cache.items); got > 2 {
		t.Fatalf("expected permission cache to cap entries at 2, got %d", got)
	}
	if inner.calls != 3 {
		t.Fatalf("expected 3 backend calls for 3 unique keys, got %d", inner.calls)
	}
}

func TestPermissionCacheHitsWithoutBackendCall(t *testing.T) {
	inner := &stubPolicyStore{}
	cache := New(inner, time.Minute)

	_, _ = cache.GetUserPermissions(context.Background(), "u1", "t1")
	_, _ = cache.GetUserPermissions(context.Background(), "u1", "t1")

	if inner.calls != 1 {
		t.Fatalf("expected second lookup to hit cache, backend calls=%d", inner.calls)
	}
}

func TestPermissionCacheDisabledWhenTTLZero(t *testing.T) {
	inner := &stubPolicyStore{}
	cache := New(inner, 0)

	_, _ = cache.GetUserPermissions(context.Background(), "u1", "t1")
	_, _ = cache.GetUserPermissions(context.Background(), "u1", "t1")

	if inner.calls != 2 {
		t.Fatalf("expected disabled cache to hit backend twice, got %d", inner.calls)
	}
	if got := len(cache.items); got != 0 {
		t.Fatalf("expected disabled cache to keep no entries, got %d", got)
	}
}
