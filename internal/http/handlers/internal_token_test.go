package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsTokenMiddlewareAllowsLoopbackWithoutToken(t *testing.T) {
	router := NewRouter(RouterParams{
		Engine:        &captureEngine{},
		EnableMetrics: true,
		InternalToken: "internal-secret",
		MetricsToken:  "metrics-secret",
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on loopback metrics access, got %d", rr.Code)
	}
}

func TestMetricsTokenMiddlewareRequiresDedicatedTokenOffLoopback(t *testing.T) {
	router := NewRouter(RouterParams{
		Engine:        &captureEngine{},
		EnableMetrics: true,
		InternalToken: "internal-secret",
		MetricsToken:  "metrics-secret",
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with only internal token, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("X-Metrics-Token", "metrics-secret")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with dedicated metrics token, got %d", rr.Code)
	}
}
