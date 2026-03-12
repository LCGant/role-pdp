package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LCGant/role-pdp/internal/authz"
)

type captureEngine struct {
	lastReq authz.DecisionRequest
}

func (e *captureEngine) Decide(ctx context.Context, req authz.DecisionRequest) (authz.DecisionResponse, error) {
	e.lastReq = req
	return authz.DecisionResponse{Allow: true, Reason: "rbac:test"}, nil
}

func TestDecisionRequiresInternalToken(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}
}

func TestDecisionContextPreservesPayloadIPWhenProvided(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"},"context":{"ip":"203.0.113.77","method":"PATCH","path":"/forged","user_agent":"unit-test-payload"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "unit-test")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if engine.lastReq.Context.IP != "203.0.113.77" {
		t.Fatalf("expected payload ip to be preserved, got %q", engine.lastReq.Context.IP)
	}
	if engine.lastReq.Context.Method != "PATCH" {
		t.Fatalf("expected payload method to be preserved, got %q", engine.lastReq.Context.Method)
	}
	if engine.lastReq.Context.Path != "/forged" {
		t.Fatalf("expected payload path to be preserved, got %q", engine.lastReq.Context.Path)
	}
	if engine.lastReq.Context.UserAgent != "unit-test-payload" {
		t.Fatalf("expected payload user agent to be preserved, got %q", engine.lastReq.Context.UserAgent)
	}

	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !out.Allow {
		t.Fatalf("expected allow response, got %+v", out)
	}
}

func TestDecisionContextRemainsEmptyWhenPayloadMissing(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "unit-test")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if engine.lastReq.Context.IP != "" || engine.lastReq.Context.Method != "" || engine.lastReq.Context.Path != "" || engine.lastReq.Context.UserAgent != "" {
		t.Fatalf("expected missing context to remain empty, got %+v", engine.lastReq.Context)
	}
}

func TestDecisionRejectsTrailingJSON(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"}}{"extra":1}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing JSON, got %d", rr.Code)
	}
}
