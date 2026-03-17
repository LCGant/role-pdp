package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/observability"
)

type DecisionHandler struct {
	engine   authz.Engine
	logger   *slog.Logger
	limiter  *RateLimiter
	enricher RequestEnricher
}

func NewDecisionHandler(engine authz.Engine, logger *slog.Logger, limiter *RateLimiter, enricher RequestEnricher) *DecisionHandler {
	return &DecisionHandler{
		engine:   engine,
		logger:   logger,
		limiter:  limiter,
		enricher: enricher,
	}
}

func (h *DecisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req authz.DecisionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	start := time.Now()
	req.Action = normalizeAction(req.Action)
	ensureContextDefaults(&req, r)
	if err := validateDecisionRequest(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if h.limiter != nil {
		if !h.limiter.Allow(rateLimitKey(r)) {
			respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
	}
	if denyResp, err := enrichDecisionRequest(r.Context(), h.enricher, &req); err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "decision enrichment failed", "error", err, "request_id", RequestIDFromContext(r.Context()))
		}
		respondError(w, http.StatusInternalServerError, "failed to enrich decision")
		return
	} else if denyResp != nil {
		respondJSON(w, http.StatusOK, *denyResp)
		return
	}

	resp, err := h.engine.Decide(r.Context(), req)
	if err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "decision evaluation failed", "error", err, "request_id", RequestIDFromContext(r.Context()))
		}
		respondError(w, http.StatusInternalServerError, "failed to evaluate decision")
		return
	}

	observability.RecordLatency(req.Action, time.Since(start).Milliseconds())
	respondJSON(w, http.StatusOK, resp)
}

func ensureContextDefaults(req *authz.DecisionRequest, r *http.Request) {
	req.Normalize()
}

func validateDecisionRequest(req authz.DecisionRequest) error {
	req.Normalize()
	if strings.TrimSpace(req.Subject.UserID) == "" {
		return errors.New("subject.user_id is required")
	}
	if strings.TrimSpace(req.Subject.TenantID) == "" {
		return errors.New("subject.tenant_id is required")
	}
	if req.Action == "" {
		return errors.New("action is required")
	}
	if strings.TrimSpace(req.Resource.Type) == "" {
		return errors.New("resource.type is required")
	}
	if resourceIDRequired(req.Action, req.Resource) && strings.TrimSpace(req.Resource.ID) == "" {
		return errors.New("resource.id is required")
	}
	if strings.TrimSpace(req.Resource.TenantID) == "" {
		return errors.New("resource.tenant_id is required")
	}
	return nil
}

func resourceIDRequired(action string, res authz.Resource) bool {
	if strings.TrimSpace(res.ID) != "" {
		return false
	}
	switch action {
	case "create", "list", "search":
		return false
	}
	if strings.HasSuffix(action, ":create") || strings.HasSuffix(action, ":list") || strings.HasSuffix(action, ":search") {
		return false
	}
	return true
}
