package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/LCGant/role-pdp/internal/authz"
)

type RouterParams struct {
	Logger         *slog.Logger
	Engine         authz.Engine
	EnableMetrics  bool
	RateLimiter    *RateLimiter
	Readiness      http.Handler
	AdminToken     string
	InternalToken  string
	MetricsToken   string
	Caches         []CacheClearer
	AdminStore     AdminStore
	ClientIDHeader string
}

func NewRouter(params RouterParams) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(HealthHandler))
	if params.Readiness != nil {
		mux.Handle("/readyz", params.Readiness)
	}
	if params.AdminToken != "" {
		mux.Handle("/v1/admin/cache/clear", NewAdminHandler(params.AdminToken, params.Caches, params.RateLimiter))
	}
	if params.AdminStore != nil && params.AdminToken != "" {
		api := &AdminAPI{
			Token:   params.AdminToken,
			Store:   params.AdminStore,
			limiter: params.RateLimiter,
			caches:  params.Caches,
		}
		mux.Handle("/v1/admin/roles", api)
		mux.Handle("/v1/admin/permissions", api)
		mux.Handle("/v1/admin/roles/permissions", api)
		mux.Handle("/v1/admin/user-roles", api)
	} else {
		mux.Handle("/v1/admin/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respondError(w, http.StatusServiceUnavailable, "admin endpoints disabled")
		}))
	}
	decision := NewDecisionHandler(params.Engine, params.Logger, params.RateLimiter)
	batch := NewBatchDecisionHandler(params.Engine, params.Logger, params.RateLimiter)
	decisionHandler := internalTokenMiddleware(params.InternalToken)(decision)
	batchHandler := internalTokenMiddleware(params.InternalToken)(batch)
	mux.Handle("/v1/decision", decisionHandler)
	mux.Handle("/v1/batch-decision", batchHandler)

	if params.EnableMetrics {
		mux.Handle("/metrics", metricsTokenMiddleware(params.MetricsToken)(MetricsHandler()))
	}

	var handler http.Handler = mux
	handler = RequestIDMiddleware(handler)
	if params.ClientIDHeader != "" {
		handler = clientIDMiddleware(params.ClientIDHeader)(handler)
	}
	handler = LoggingMiddleware(params.Logger)(handler)
	handler = RecoveryMiddleware(params.Logger)(handler)
	return handler
}

func clientIDMiddleware(headerName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), contextKey("clientIDHeader"), headerName)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
