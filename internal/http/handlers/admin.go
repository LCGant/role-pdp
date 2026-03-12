package handlers

import (
	"crypto/subtle"
	"net/http"
)

type CacheClearer interface {
	Clear()
}

type AdminHandler struct {
	Token   string
	Caches  []CacheClearer
	limiter *RateLimiter
}

func NewAdminHandler(token string, caches []CacheClearer, limiter *RateLimiter) *AdminHandler {
	return &AdminHandler{Token: token, Caches: caches, limiter: limiter}
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.limiter != nil && !h.limiter.Allow(rateLimitAdminPreAuthKey(r)) {
		respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if h.Token == "" {
		respondError(w, http.StatusUnauthorized, "admin token not configured")
		return
	}
	header := r.Header.Get("X-Admin-Token")
	if header == "" || len(header) != len(h.Token) || subtle.ConstantTimeCompare([]byte(header), []byte(h.Token)) != 1 {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.limiter != nil && !h.limiter.Allow(rateLimitAdminKey(r)) {
		respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	for _, c := range h.Caches {
		if c != nil {
			c.Clear()
		}
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "cache_cleared"})
}
