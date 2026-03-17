package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/social"
)

type captureEngine struct {
	lastReq authz.DecisionRequest
}

type stubEnricher struct {
	fn func(context.Context, *authz.DecisionRequest) error
}

func (e *captureEngine) Decide(ctx context.Context, req authz.DecisionRequest) (authz.DecisionResponse, error) {
	e.lastReq = req
	return authz.DecisionResponse{Allow: true, Reason: "rbac:test"}, nil
}

func (s stubEnricher) Enrich(ctx context.Context, req *authz.DecisionRequest) error {
	if s.fn == nil {
		return nil
	}
	return s.fn(ctx, req)
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
	if engine.lastReq.Subject.ActorID != "u1" || engine.lastReq.Subject.ActorType != "person" {
		t.Fatalf("expected default actor principal to be normalized, got %+v", engine.lastReq.Subject)
	}
}

func TestDecisionPreservesExplicitActorAndRelationships(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
		Enricher:      stubEnricher{},
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1","actor_id":"business-7","actor_type":"business"},"action":"profiles:read","resource":{"type":"profiles","id":"p1","tenant_id":"t1","owner_actor_id":"u2","visibility":"friends_only"},"relationships":{"friend":true}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if engine.lastReq.Subject.ActorID != "business-7" || engine.lastReq.Subject.ActorType != "business" {
		t.Fatalf("expected explicit actor to be preserved, got %+v", engine.lastReq.Subject)
	}
	if engine.lastReq.Resource.OwnerActorID != "u2" || engine.lastReq.Resource.Visibility != "friends_only" {
		t.Fatalf("expected social resource context to be preserved, got %+v", engine.lastReq.Resource)
	}
	if !engine.lastReq.Relationships.Friend {
		t.Fatalf("expected friend relationship to be preserved, got %+v", engine.lastReq.Relationships)
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

func TestDecisionEnricherOverridesProfileSocialContext(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
		Enricher: stubEnricher{fn: func(ctx context.Context, req *authz.DecisionRequest) error {
			req.Resource.OwnerActorID = "u2"
			req.Resource.OwnerActorType = "person"
			req.Resource.Visibility = "private"
			req.Relationships = authz.RelationshipInfo{Blocked: true}
			return nil
		}},
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"profiles:read","resource":{"type":"profiles","id":"alice","tenant_id":"t1","owner_actor_id":"spoofed","visibility":"public"},"relationships":{"friend":true}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if engine.lastReq.Resource.OwnerActorID != "u2" || engine.lastReq.Resource.Visibility != "private" {
		t.Fatalf("expected enriched profile context to override caller values, got %+v", engine.lastReq.Resource)
	}
	if !engine.lastReq.Relationships.Blocked || engine.lastReq.Relationships.Friend {
		t.Fatalf("expected enriched relationships to replace caller-provided social state, got %+v", engine.lastReq.Relationships)
	}
}

func TestDecisionProfileNotFoundReturnsDeny(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
		Enricher: stubEnricher{fn: func(ctx context.Context, req *authz.DecisionRequest) error {
			return social.ErrNotFound
		}},
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"profiles:read","resource":{"type":"profiles","id":"missing","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Allow || out.Reason != "resource_not_found" {
		t.Fatalf("expected resource_not_found deny, got %+v", out)
	}
}

func TestDecisionProfilesFailClosedWithoutSocialEnricher(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"profiles:read","resource":{"type":"profiles","id":"alice","tenant_id":"t1","owner_actor_id":"u2","visibility":"public"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Allow || out.Reason != "social_context_unavailable" {
		t.Fatalf("expected social_context_unavailable deny, got %+v", out)
	}
}

func TestDecisionPlaylistsFailClosedWithoutSocialEnricher(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"playlists:read","resource":{"type":"playlists","id":"99","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Allow || out.Reason != "social_context_unavailable" {
		t.Fatalf("expected social_context_unavailable deny, got %+v", out)
	}
}

func TestDecisionEventsFailClosedWithoutSocialEnricher(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"events:read","resource":{"type":"events","id":"7","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Allow || out.Reason != "social_context_unavailable" {
		t.Fatalf("expected social_context_unavailable deny, got %+v", out)
	}
}

func TestDecisionPostsFailClosedWithoutSocialEnricher(t *testing.T) {
	engine := &captureEngine{}
	router := NewRouter(RouterParams{
		Engine:        engine,
		EnableMetrics: false,
		InternalToken: "internal-secret",
	})

	body := `{"subject":{"user_id":"u1","tenant_id":"t1"},"action":"posts:read","resource":{"type":"posts","id":"10","tenant_id":"t1"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/decision", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", "internal-secret")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out authz.DecisionResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Allow || out.Reason != "social_context_unavailable" {
		t.Fatalf("expected social_context_unavailable deny, got %+v", out)
	}
}
