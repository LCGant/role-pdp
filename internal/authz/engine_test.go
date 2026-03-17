package authz

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/observability"
	"github.com/LCGant/role-pdp/internal/store"
)

func TestEngineRBACAllow(t *testing.T) {
	st := &stubStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", TenantID: "tenant-1"},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !resp.Allow {
		t.Fatalf("expected allow, got deny: %+v", resp)
	}
	if resp.Reason == "" {
		t.Fatalf("expected reason to be set")
	}
}

func TestEngineOwnershipFallback(t *testing.T) {
	st := &stubStore{perms: []string{}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject: Subject{UserID: "owner", TenantID: "tenant-1", AAL: 1},
		Action:  "orders:update",
		Resource: Resource{
			Type:     "orders",
			TenantID: "tenant-1",
			OwnerID:  "owner",
		},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !resp.Allow || resp.Reason != "owner_update" {
		t.Fatalf("expected owner-based allow, got %+v", resp)
	}
}

func TestEngineActorOwnershipFallback(t *testing.T) {
	st := &stubStore{perms: []string{}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject: Subject{
			UserID:    "user-1",
			TenantID:  "tenant-1",
			ActorID:   "business-42",
			ActorType: "business",
			AAL:       1,
		},
		Action: "profiles:update",
		Resource: Resource{
			Type:           "profiles",
			ID:             "p-1",
			TenantID:       "tenant-1",
			OwnerActorID:   "business-42",
			OwnerActorType: "business",
		},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !resp.Allow || resp.Reason != "owner_update" {
		t.Fatalf("expected actor-owner allow, got %+v", resp)
	}
}

func TestEngineBlockedRelationshipDeniesBeforeAllow(t *testing.T) {
	st := &stubStore{perms: []string{"profiles:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "profiles:read",
		Resource: Resource{Type: "profiles", ID: "profile-2", TenantID: "tenant-1", OwnerActorID: "user-2", Visibility: "public"},
		Relationships: RelationshipInfo{
			Blocked: true,
		},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp.Allow || resp.Reason != "blocked" {
		t.Fatalf("expected blocked deny, got %+v", resp)
	}
}

func TestEngineRelationshipVisibilityAllowsRead(t *testing.T) {
	st := &stubStore{perms: []string{}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "profiles:read",
		Resource: Resource{Type: "profiles", ID: "profile-2", TenantID: "tenant-1", OwnerActorID: "user-2", Visibility: "friends_only"},
		Relationships: RelationshipInfo{
			Friend: true,
		},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !resp.Allow || resp.Reason != "visibility_friends" {
		t.Fatalf("expected relation-based allow, got %+v", resp)
	}
}

func TestEngineRelationshipVisibilityDeniesRead(t *testing.T) {
	st := &stubStore{perms: []string{}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true, StepUpMaxAge: 0})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "profiles:read",
		Resource: Resource{Type: "profiles", ID: "profile-2", TenantID: "tenant-1", OwnerActorID: "user-2", Visibility: "private"},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp.Allow || resp.Reason != "visibility_denied" {
		t.Fatalf("expected visibility deny, got %+v", resp)
	}
}

func TestEngineStepUpRequired(t *testing.T) {
	st := &stubStore{perms: []string{"admin:delete"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{EnableOwnershipCheck: true})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1, AuthTime: time.Now().Add(-10 * time.Minute)},
		Action:   "admin:delete",
		Resource: Resource{Type: "admin", TenantID: "tenant-1"},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp.Allow {
		t.Fatalf("expected deny for step-up requirement")
	}
	if resp.Reason != "step_up_required" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
	if resp.Obligations["require_aal"] != 2 {
		t.Fatalf("expected require_aal=2, got %+v", resp.Obligations)
	}
}

func TestEngineReauthRequiredWhenAuthTimeMissing(t *testing.T) {
	st := &stubStore{perms: []string{"admin:delete"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{
		EnableOwnershipCheck: true,
		StepUpMaxAge:         10 * time.Minute,
	})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 2},
		Action:   "admin:delete",
		Resource: Resource{Type: "admin", TenantID: "tenant-1"},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp.Allow {
		t.Fatalf("expected deny when auth_time is missing")
	}
	if resp.Reason != "reauth_required" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestEngineTenantMismatchBypassesCache(t *testing.T) {
	cache := NewDecisionCache(time.Minute)
	if cache == nil {
		t.Fatal("expected decision cache")
	}
	st := &stubStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{
		EnableOwnershipCheck: true,
		Cache:                cache,
	})

	allowReq := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "123", TenantID: "tenant-1"},
	}
	allowResp, err := engine.Decide(context.Background(), allowReq)
	if err != nil {
		t.Fatalf("allow decide: %v", err)
	}
	if !allowResp.Allow {
		t.Fatalf("expected cached source allow, got %+v", allowResp)
	}

	mismatchReq := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "123", TenantID: "tenant-2"},
	}
	mismatchResp, err := engine.Decide(context.Background(), mismatchReq)
	if err != nil {
		t.Fatalf("mismatch decide: %v", err)
	}
	if mismatchResp.Allow {
		t.Fatalf("expected tenant mismatch deny, got %+v", mismatchResp)
	}
	if mismatchResp.Reason != "tenant_mismatch" {
		t.Fatalf("expected tenant_mismatch reason, got %q", mismatchResp.Reason)
	}
}

func TestEngineAppliesContextPolicyFromOptions(t *testing.T) {
	policy := ContextPolicy{
		ActionPrefix: "orders:",
		AllowCIDRs:   []string{"10.0.0.0/8"},
	}
	if err := policy.normalize(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}

	st := &stubStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{
		EnableOwnershipCheck: true,
		ContextPolicies:      []ContextPolicy{policy},
	})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "123", TenantID: "tenant-1"},
		Context:  ContextInfo{IP: "203.0.113.5"},
	}
	resp, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if resp.Allow {
		t.Fatalf("expected context policy deny, got allow")
	}
	if resp.Reason != "context_denied" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestEngineSkipsCacheWhenContextPolicyMatchesAction(t *testing.T) {
	cache := NewDecisionCache(time.Minute)
	if cache == nil {
		t.Fatal("expected decision cache")
	}
	policy := ContextPolicy{
		ActionPrefix: "orders:",
		AllowCIDRs:   []string{"10.0.0.0/8"},
	}
	if err := policy.normalize(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}

	st := &stubStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{
		EnableOwnershipCheck: true,
		Cache:                cache,
		ContextPolicies:      []ContextPolicy{policy},
	})

	baseReq := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "123", TenantID: "tenant-1"},
	}

	allowReq := baseReq
	allowReq.Context.IP = "10.1.2.3"
	allowResp, err := engine.Decide(context.Background(), allowReq)
	if err != nil {
		t.Fatalf("allow decide: %v", err)
	}
	if !allowResp.Allow {
		t.Fatalf("expected allow, got %+v", allowResp)
	}

	denyReq := baseReq
	denyReq.Context.IP = "203.0.113.5"
	denyResp, err := engine.Decide(context.Background(), denyReq)
	if err != nil {
		t.Fatalf("deny decide: %v", err)
	}
	if denyResp.Allow || denyResp.Reason != "context_denied" {
		t.Fatalf("expected context_denied, got %+v", denyResp)
	}
	if st.getCalls != 2 {
		t.Fatalf("expected store to be called twice when cache is bypassed, got %d", st.getCalls)
	}
}

func TestEngineUsesCacheWhenNoContextPolicyMatchesAction(t *testing.T) {
	cache := NewDecisionCache(time.Minute)
	if cache == nil {
		t.Fatal("expected decision cache")
	}
	policy := ContextPolicy{
		ActionPrefix: "admin:",
		AllowCIDRs:   []string{"10.0.0.0/8"},
	}
	if err := policy.normalize(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}

	st := &stubStore{perms: []string{"orders:read"}}
	engine := NewEngine(st, &observability.AuditLogger{Sink: st}, testLogger(), &Options{
		EnableOwnershipCheck: true,
		Cache:                cache,
		ContextPolicies:      []ContextPolicy{policy},
	})

	req := DecisionRequest{
		Subject:  Subject{UserID: "user-1", TenantID: "tenant-1", AAL: 1},
		Action:   "orders:read",
		Resource: Resource{Type: "orders", ID: "123", TenantID: "tenant-1"},
		Context:  ContextInfo{IP: "203.0.113.5"},
	}
	resp1, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	resp2, err := engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if !resp1.Allow || !resp2.Allow {
		t.Fatalf("expected allow on both decisions, got %+v and %+v", resp1, resp2)
	}
	if st.getCalls != 1 {
		t.Fatalf("expected one store call due to cache hit, got %d", st.getCalls)
	}
}

type stubStore struct {
	perms    []string
	audits   []store.AuditLogEntry
	getCalls int
}

func (s *stubStore) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	s.getCalls++
	return s.perms, nil
}

func (s *stubStore) LogDecision(ctx context.Context, entry store.AuditLogEntry) error {
	s.audits = append(s.audits, entry)
	return nil
}

func (s *stubStore) Close() error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
