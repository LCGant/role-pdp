package authz

import (
	"testing"
	"time"
)

func TestDecisionCacheCapsEntries(t *testing.T) {
	cache := NewDecisionCache(time.Minute)
	if cache == nil {
		t.Fatal("expected cache instance")
	}
	cache.maxEntries = 2

	req1 := DecisionRequest{
		Subject:  Subject{UserID: "u1", TenantID: "t1"},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "1", TenantID: "t1"},
	}
	req2 := DecisionRequest{
		Subject:  Subject{UserID: "u2", TenantID: "t1"},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "2", TenantID: "t1"},
	}
	req3 := DecisionRequest{
		Subject:  Subject{UserID: "u3", TenantID: "t1"},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "3", TenantID: "t1"},
	}
	resp := DecisionResponse{Allow: true, Reason: "rbac:orders:read"}

	cache.Set(req1, resp)
	time.Sleep(2 * time.Millisecond)
	cache.Set(req2, resp)
	time.Sleep(2 * time.Millisecond)
	cache.Set(req3, resp)

	if got := len(cache.entries); got > 2 {
		t.Fatalf("expected decision cache to cap entries at 2, got %d", got)
	}
	if _, ok := cache.entries[decisionCacheKey(req3)]; !ok {
		t.Fatalf("expected newest key to remain cached")
	}
}
