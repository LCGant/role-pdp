package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LCGant/role-pdp/internal/authz"
)

func TestBatchDecisionRejectsTooManyRequests(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	type payload struct {
		Requests []authz.DecisionRequest `json:"requests"`
	}
	reqs := make([]authz.DecisionRequest, 0, maxBatchDecisionRequests+1)
	for i := 0; i < maxBatchDecisionRequests+1; i++ {
		reqs = append(reqs, authz.DecisionRequest{
			Subject:  authz.Subject{UserID: "u1", TenantID: "t1"},
			Action:   "orders:list",
			Resource: authz.Resource{Type: "orders", TenantID: "t1"},
		})
	}
	body, err := json.Marshal(payload{Requests: reqs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/batch-decision", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestBatchDecisionPreservesPayloadIPWhenProvided(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"requests":[{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"},"context":{"ip":"203.0.113.77","method":"PATCH","path":"/forged","user_agent":"batch-payload"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/batch-decision", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("Content-Type", "application/json")
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
	if engine.lastReq.Context.UserAgent != "batch-payload" {
		t.Fatalf("expected payload user agent to be preserved, got %q", engine.lastReq.Context.UserAgent)
	}
}

func TestBatchDecisionContextRemainsEmptyWhenPayloadMissing(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"requests":[{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"orders:list","resource":{"type":"orders","tenant_id":"t1"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/batch-decision", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:4321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if engine.lastReq.Context.IP != "" || engine.lastReq.Context.Method != "" || engine.lastReq.Context.Path != "" || engine.lastReq.Context.UserAgent != "" {
		t.Fatalf("expected missing batch context to remain empty, got %+v", engine.lastReq.Context)
	}
}
