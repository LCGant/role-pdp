package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminCacheClearRateLimited(t *testing.T) {
	rl := NewRateLimiter(60, 1)
	if rl == nil {
		t.Fatalf("expected limiter")
	}
	h := NewAdminHandler("secret", nil, rl)

	req1 := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/clear", nil)
	req1.RemoteAddr = "198.51.100.4:4444"
	req1.Header.Set("X-Admin-Token", "secret")
	req1.Header.Set("X-Internal-Token", "a")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request ok, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/admin/cache/clear", nil)
	req2.RemoteAddr = "198.51.100.4:4444"
	req2.Header.Set("X-Admin-Token", "secret")
	req2.Header.Set("X-Internal-Token", "b")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", rr2.Code)
	}
}
