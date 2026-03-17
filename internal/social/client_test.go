package social

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/config"
)

func TestClientEnrichHydratesProfileDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "secret" {
			t.Fatalf("unexpected internal token")
		}
		if r.Header.Get("X-User-Id") != "u1" {
			t.Fatalf("unexpected user id header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"profile":{"actor_id":"u2","actor_type":"person","visibility":"private"},"viewer_blocked":true,"viewer_follows":true,"viewer_friend":true}`))
	}))
	defer srv.Close()

	client := NewClient(config.Config{
		SocialBaseURL:       srv.URL,
		SocialInternalToken: "secret",
		SocialTimeout:       time.Second,
	})
	req := authz.DecisionRequest{
		Subject:  authz.Subject{UserID: "u1", TenantID: "t1"},
		Action:   "profiles:read",
		Resource: authz.Resource{Type: "profiles", ID: "alice", TenantID: "t1", Visibility: "public"},
		Relationships: authz.RelationshipInfo{
			Friend: true,
		},
	}

	if err := client.Enrich(context.Background(), &req); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if req.Resource.OwnerActorID != "u2" || req.Resource.Visibility != "private" {
		t.Fatalf("expected enriched resource context, got %+v", req.Resource)
	}
	if !req.Relationships.Blocked || !req.Relationships.Friend || !req.Relationships.Following {
		t.Fatalf("expected enriched relationship state to replace caller state, got %+v", req.Relationships)
	}
}

func TestClientEnrichReturnsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := NewClient(config.Config{
		SocialBaseURL:       srv.URL,
		SocialInternalToken: "secret",
		SocialTimeout:       time.Second,
	})
	req := authz.DecisionRequest{
		Subject:  authz.Subject{UserID: "u1", TenantID: "t1"},
		Action:   "profiles:read",
		Resource: authz.Resource{Type: "profiles", ID: "missing", TenantID: "t1"},
	}
	if err := client.Enrich(context.Background(), &req); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
