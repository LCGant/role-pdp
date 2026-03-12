package handlers

import (
	"log/slog"
	"net/http"

	"github.com/LCGant/role-pdp/internal/authz"
)

type BatchDecisionRequest struct {
	Requests []authz.DecisionRequest `json:"requests"`
}

type BatchDecisionResponse struct {
	Decisions []authz.DecisionResponse `json:"decisions"`
}

const maxBatchDecisionRequests = 100

type BatchDecisionHandler struct {
	engine  authz.Engine
	logger  *slog.Logger
	limiter *RateLimiter
}

func NewBatchDecisionHandler(engine authz.Engine, logger *slog.Logger, limiter *RateLimiter) *BatchDecisionHandler {
	return &BatchDecisionHandler{engine: engine, logger: logger, limiter: limiter}
}

func (h *BatchDecisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req BatchDecisionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Requests) == 0 {
		respondError(w, http.StatusBadRequest, "requests cannot be empty")
		return
	}
	if len(req.Requests) > maxBatchDecisionRequests {
		respondError(w, http.StatusBadRequest, "too many requests in batch")
		return
	}
	if h.limiter != nil && !h.limiter.Allow(rateLimitKey(r)) {
		respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	decisions := make([]authz.DecisionResponse, 0, len(req.Requests))
	for _, single := range req.Requests {
		single.Action = normalizeAction(single.Action)
		ensureContextDefaults(&single, r)
		if err := validateDecisionRequest(single); err != nil {
			decisions = append(decisions, authz.DecisionResponse{
				Allow:  false,
				Reason: "invalid_request",
			})
			continue
		}
		resp, err := h.engine.Decide(r.Context(), single)
		if err != nil {
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "batch decision failed", "error", err)
			}
			decisions = append(decisions, authz.DecisionResponse{
				Allow:  false,
				Reason: "error_evaluating",
			})
			continue
		}
		decisions = append(decisions, resp)
	}

	respondJSON(w, http.StatusOK, BatchDecisionResponse{Decisions: decisions})
}
