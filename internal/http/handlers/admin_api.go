package handlers

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

type AdminStore interface {
	CreateRole(r *http.Request, tenantID, name string) error
	CreatePermission(r *http.Request, name string) error
	GrantPermission(r *http.Request, roleName, tenantID, permName string) error
	AssignUserRole(r *http.Request, userID, tenantID, roleName string) error
}

type AdminAPI struct {
	Token   string
	Store   AdminStore
	limiter *RateLimiter
	caches  []CacheClearer
}

type roleRequest struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

type permissionRequest struct {
	Name string `json:"name"`
}

type grantRequest struct {
	RoleName string `json:"role"`
	TenantID string `json:"tenant_id"`
	PermName string `json:"permission"`
}

type assignRoleRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	RoleName string `json:"role"`
}

func (a *AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.limiter != nil && !a.limiter.Allow(rateLimitAdminPreAuthKey(r)) {
		respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if !a.authorized(r) {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// After authentication, prefer an explicit client identifier when available to
	// avoid one noisy internal caller throttling every peer behind the same NAT/proxy.
	if a.limiter != nil && !a.limiter.Allow(rateLimitAdminKey(r)) {
		respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	path := normalizeAdminPath(r.URL.Path)
	switch {
	case r.Method == http.MethodPost && path == "/v1/admin/roles/permissions":
		a.handleGrantPermission(w, r)
	case r.Method == http.MethodPost && path == "/v1/admin/roles":
		a.handleCreateRole(w, r)
	case r.Method == http.MethodPost && path == "/v1/admin/permissions":
		a.handleCreatePermission(w, r)
	case r.Method == http.MethodPost && path == "/v1/admin/user-roles":
		a.handleAssignRole(w, r)
	default:
		respondError(w, http.StatusNotFound, "not found")
	}
}

func (a *AdminAPI) authorized(r *http.Request) bool {
	if a.Token == "" {
		return false
	}
	header := r.Header.Get("X-Admin-Token")
	if header == "" {
		return false
	}
	if len(header) != len(a.Token) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(header), []byte(a.Token)) == 1 {
		return true
	}
	return false
}

func (a *AdminAPI) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if err := decodeAdminJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := a.Store.CreateRole(r, req.TenantID, req.Name); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create role")
		return
	}
	a.invalidateCaches()
	respondJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (a *AdminAPI) handleCreatePermission(w http.ResponseWriter, r *http.Request) {
	var req permissionRequest
	if err := decodeAdminJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := a.Store.CreatePermission(r, req.Name); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create permission")
		return
	}
	a.invalidateCaches()
	respondJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (a *AdminAPI) handleGrantPermission(w http.ResponseWriter, r *http.Request) {
	var req grantRequest
	if err := decodeAdminJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RoleName == "" || req.PermName == "" {
		respondError(w, http.StatusBadRequest, "role and permission are required")
		return
	}
	if err := a.Store.GrantPermission(r, req.RoleName, req.TenantID, req.PermName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondError(w, http.StatusNotFound, "role or permission not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "failed to grant permission")
		return
	}
	a.invalidateCaches()
	respondJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (a *AdminAPI) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	var req assignRoleRequest
	if err := decodeAdminJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" || req.TenantID == "" || req.RoleName == "" {
		respondError(w, http.StatusBadRequest, "user_id, tenant_id, role are required")
		return
	}
	if err := a.Store.AssignUserRole(r, req.UserID, req.TenantID, req.RoleName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondError(w, http.StatusNotFound, "role not found for tenant")
			return
		}
		respondError(w, http.StatusInternalServerError, "failed to assign role")
		return
	}
	a.invalidateCaches()
	respondJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (a *AdminAPI) invalidateCaches() {
	for _, c := range a.caches {
		if c != nil {
			c.Clear()
		}
	}
}

// AdminAdapter wraps postgres Store to match AdminStore interface using http.Request context.
type AdminAdapter struct {
	Inner interface {
		CreateRole(ctx context.Context, tenantID, name string) error
		CreatePermission(ctx context.Context, name string) error
		GrantPermission(ctx context.Context, roleName, tenantID, permName string) error
		AssignUserRole(ctx context.Context, userID, tenantID, roleName string) error
	}
}

func (a AdminAdapter) CreateRole(r *http.Request, tenantID, name string) error {
	return a.Inner.CreateRole(r.Context(), tenantID, name)
}
func (a AdminAdapter) CreatePermission(r *http.Request, name string) error {
	return a.Inner.CreatePermission(r.Context(), name)
}
func (a AdminAdapter) GrantPermission(r *http.Request, roleName, tenantID, permName string) error {
	return a.Inner.GrantPermission(r.Context(), roleName, tenantID, permName)
}
func (a AdminAdapter) AssignUserRole(r *http.Request, userID, tenantID, roleName string) error {
	return a.Inner.AssignUserRole(r.Context(), userID, tenantID, roleName)
}

// Decode helper with strict JSON check for admin endpoints.
func decodeAdminJSON(r *http.Request, dst interface{}) error {
	return decodeJSONBody(r, dst)
}

func normalizeAdminPath(path string) string {
	if path == "" {
		return "/"
	}
	if len(path) == 1 {
		return path
	}
	return strings.TrimRight(path, "/")
}
