package handlers

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubAdminStore struct {
	createdRole bool
	err         error
}

type stubCache struct {
	clears int
}

func (s *stubCache) Clear() {
	s.clears++
}

func (s *stubAdminStore) CreateRole(r *http.Request, tenantID, name string) error {
	s.createdRole = true
	return s.err
}
func (s *stubAdminStore) CreatePermission(r *http.Request, name string) error { return s.err }
func (s *stubAdminStore) GrantPermission(r *http.Request, roleName, tenantID, permName string) error {
	return s.err
}
func (s *stubAdminStore) AssignUserRole(r *http.Request, userID, tenantID, roleName string) error {
	return s.err
}

func TestAdminAPI_TokenRequired(t *testing.T) {
	store := &stubAdminStore{}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAdminAPI_TokenSuccess(t *testing.T) {
	store := &stubAdminStore{}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	if !store.createdRole {
		t.Fatalf("expected role creation")
	}
}

func TestAdminAPI_GrantPermissionNotFound(t *testing.T) {
	store := &stubAdminStore{err: sql.ErrNoRows}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles/permissions", bytes.NewBufferString(`{"role":"admin","tenant_id":"t1","permission":"orders:read"}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestAdminAPI_AssignRoleNotFound(t *testing.T) {
	store := &stubAdminStore{err: sql.ErrNoRows}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/user-roles", bytes.NewBufferString(`{"user_id":"u1","tenant_id":"t1","role":"missing"}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestAdminAPI_RejectsTrailingJSON(t *testing.T) {
	store := &stubAdminStore{}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}{"extra":1}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestAdminAPI_DoesNotMatchPrefixLookalikePaths(t *testing.T) {
	store := &stubAdminStore{}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/rolesx", bytes.NewBufferString(`{"name":"admin"}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
	if store.createdRole {
		t.Fatalf("expected no role creation for unmatched path")
	}
}

func TestAdminAPI_ClearsCachesAfterMutation(t *testing.T) {
	store := &stubAdminStore{}
	cacheA := &stubCache{}
	cacheB := &stubCache{}
	handler := &AdminAPI{
		Token:  "secret",
		Store:  store,
		caches: []CacheClearer{cacheA, cacheB},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}`))
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	if cacheA.clears != 1 || cacheB.clears != 1 {
		t.Fatalf("expected caches to be cleared once, got A=%d B=%d", cacheA.clears, cacheB.clears)
	}
}

func TestAdminAPI_PreAuthRateLimitIgnoresClientID(t *testing.T) {
	store := &stubAdminStore{}
	rl := NewRateLimiter(60, 1)
	handler := &AdminAPI{Token: "secret", Store: store, limiter: rl}

	reqA := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}`))
	reqA.RemoteAddr = "198.51.100.10:1234"
	reqA.Header.Set("X-Client-Id", "client-a")
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA)
	if rrA.Code != http.StatusUnauthorized {
		t.Fatalf("expected first unauthorized request to fail auth, got %d", rrA.Code)
	}

	reqB := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", bytes.NewBufferString(`{"name":"admin"}`))
	reqB.RemoteAddr = "198.51.100.10:1234"
	reqB.Header.Set("X-Client-Id", "client-b")
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second unauthorized request from same ip to be rate limited, got %d", rrB.Code)
	}
}

func TestAdminAPI_RejectsOversizedBody(t *testing.T) {
	store := &stubAdminStore{}
	handler := &AdminAPI{Token: "secret", Store: store}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/roles", strings.NewReader(strings.Repeat("a", maxBodyBytes+1)))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rr.Code)
	}
	if store.createdRole {
		t.Fatalf("expected oversized body to abort before store mutation")
	}
}
