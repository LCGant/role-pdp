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
		if r.Header.Get("X-Tenant-Id") != "t1" {
			t.Fatalf("unexpected tenant header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"profile":{"tenant_id":"tenant-social","actor_id":"u2","actor_type":"person","visibility":"private"},"viewer_blocked":true,"viewer_follows":true,"viewer_friend":true}`))
	}))
	defer srv.Close()

	client := NewClient(config.Config{
		SocialBaseURL:            srv.URL,
		SocialAuthzInternalToken: "secret",
		SocialTimeout:            time.Second,
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
	if req.Resource.OwnerActorID != "u2" || req.Resource.Visibility != "private" || req.Resource.TenantID != "tenant-social" {
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
		SocialBaseURL:            srv.URL,
		SocialAuthzInternalToken: "secret",
		SocialTimeout:            time.Second,
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

func TestClientEnrichHydratesPlaylistDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "secret" {
			t.Fatalf("unexpected internal token")
		}
		if r.Header.Get("X-User-Id") != "u1" {
			t.Fatalf("unexpected user id header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"playlist":{"tenant_id":"tenant-social","owner_actor_id":"u2","owner_actor_type":"person","visibility":"shared"},"viewer_blocked":false,"viewer_follows":true,"viewer_friend":false,"viewer_shared":false,"viewer_collaborator":true}`))
	}))
	defer srv.Close()

	client := NewClient(config.Config{
		SocialBaseURL:            srv.URL,
		SocialAuthzInternalToken: "secret",
		SocialTimeout:            time.Second,
	})
	req := authz.DecisionRequest{
		Subject:  authz.Subject{UserID: "u1", TenantID: "t1"},
		Action:   "playlists:read",
		Resource: authz.Resource{Type: "playlists", ID: "99", TenantID: "t1"},
	}

	if err := client.Enrich(context.Background(), &req); err != nil {
		t.Fatalf("enrich playlist: %v", err)
	}
	if req.Resource.OwnerActorID != "u2" || req.Resource.Visibility != "shared" || req.Resource.TenantID != "tenant-social" {
		t.Fatalf("expected enriched playlist resource context, got %+v", req.Resource)
	}
	if !req.Relationships.Collaborator || req.Relationships.Shared || !req.Relationships.Following || req.Relationships.Friend {
		t.Fatalf("expected enriched playlist relationships, got %+v", req.Relationships)
	}
}

func TestClientEnrichHydratesEventDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Token") != "secret" {
			t.Fatalf("unexpected internal token")
		}
		if r.Header.Get("X-User-Id") != "u1" {
			t.Fatalf("unexpected user id header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"event":{"tenant_id":"tenant-social","owner_actor_id":"u2","owner_actor_type":"person","visibility":"invite_only"},"viewer_blocked":false,"viewer_follows":true,"viewer_friend":true,"viewer_invited":true,"viewer_participant":false,"viewer_organizer":false}`))
	}))
	defer srv.Close()

	client := NewClient(config.Config{
		SocialBaseURL:            srv.URL,
		SocialAuthzInternalToken: "secret",
		SocialTimeout:            time.Second,
	})
	req := authz.DecisionRequest{
		Subject:  authz.Subject{UserID: "u1", TenantID: "t1"},
		Action:   "events:read",
		Resource: authz.Resource{Type: "events", ID: "7", TenantID: "t1"},
	}

	if err := client.Enrich(context.Background(), &req); err != nil {
		t.Fatalf("enrich event: %v", err)
	}
	if req.Resource.OwnerActorID != "u2" || req.Resource.Visibility != "invite_only" || req.Resource.TenantID != "tenant-social" {
		t.Fatalf("expected enriched event resource context, got %+v", req.Resource)
	}
	if !req.Relationships.Invited || !req.Relationships.Friend || !req.Relationships.Following || req.Relationships.Participant {
		t.Fatalf("expected enriched event relationships, got %+v", req.Relationships)
	}
}
