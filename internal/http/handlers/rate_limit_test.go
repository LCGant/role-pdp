package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterCapsTrackedEntries(t *testing.T) {
	rl := NewRateLimiter(60, 60)
	if rl == nil {
		t.Fatalf("expected limiter instance")
	}
	rl.maxEntries = 2
	rl.idleTTL = time.Hour

	if !rl.Allow("k1") {
		t.Fatalf("expected k1 allow")
	}
	if !rl.Allow("k2") {
		t.Fatalf("expected k2 allow")
	}
	if !rl.Allow("k3") {
		t.Fatalf("expected k3 allow after eviction")
	}
	if got := len(rl.bucket); got > 2 {
		t.Fatalf("expected bucket map capped at 2 entries, got %d", got)
	}
}

func TestRateLimitAdminKeySeparatesExplicitClientIDs(t *testing.T) {
	reqA := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", nil)
	reqA.RemoteAddr = "198.51.100.10:1234"
	reqA.Header.Set("X-Internal-Token", "token-a")
	reqA.Header.Set("X-Client-Id", "client-a")

	reqB := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", nil)
	reqB.RemoteAddr = "198.51.100.10:1234"
	reqB.Header.Set("X-Internal-Token", "token-b")
	reqB.Header.Set("X-Client-Id", "client-b")

	keyA := rateLimitAdminKey(reqA)
	keyB := rateLimitAdminKey(reqB)
	if keyA == keyB {
		t.Fatalf("expected admin key to isolate explicit client ids, got %q and %q", keyA, keyB)
	}
}

func TestRateLimitAdminKeyFallsBackToIPWithoutClientID(t *testing.T) {
	reqA := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", nil)
	reqA.RemoteAddr = "198.51.100.10:1234"

	reqB := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", nil)
	reqB.RemoteAddr = "198.51.100.10:1234"

	keyA := rateLimitAdminKey(reqA)
	keyB := rateLimitAdminKey(reqB)
	if keyA != keyB {
		t.Fatalf("expected same admin key by IP fallback, got %q and %q", keyA, keyB)
	}
}

func TestRateLimitKeyPrefersConfiguredClientIDBeforeInternalToken(t *testing.T) {
	reqA := httptest.NewRequest(http.MethodPost, "/v1/decision", nil)
	reqA.RemoteAddr = "198.51.100.10:1234"
	reqA.Header.Set("X-Internal-Token", "shared-token")
	reqA.Header.Set("X-Client-Id", "client-a")
	reqA = reqA.WithContext(context.WithValue(reqA.Context(), contextKey("clientIDHeader"), "X-Client-Id"))

	reqB := httptest.NewRequest(http.MethodPost, "/v1/decision", nil)
	reqB.RemoteAddr = "198.51.100.10:1234"
	reqB.Header.Set("X-Internal-Token", "shared-token")
	reqB.Header.Set("X-Client-Id", "client-b")
	reqB = reqB.WithContext(context.WithValue(reqB.Context(), contextKey("clientIDHeader"), "X-Client-Id"))

	keyA := rateLimitKey(reqA)
	keyB := rateLimitKey(reqB)
	if keyA == keyB {
		t.Fatalf("expected decision rate limit key to isolate explicit client ids, got %q and %q", keyA, keyB)
	}
}
