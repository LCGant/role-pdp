package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/LCGant/role-pdp/internal/observability"
	"github.com/LCGant/role-pdp/internal/store"
)

// Engine represents the authorization engine contract.
type Engine interface {
	Decide(ctx context.Context, req DecisionRequest) (DecisionResponse, error)
}

var ErrStoreUnavailable = errors.New("policy store unavailable")

type Options struct {
	EnableOwnershipCheck bool
	StepUpPolicies       []StepUpPolicy
	StepUpMaxAge         time.Duration
	StepUpAAL            int
	DecisionCacheTTL     time.Duration
	Cache                DecisionCacheBackend
	ContextPolicies      []ContextPolicy
}

type StepUpPolicy struct {
	ActionPrefix string        `json:"action_prefix"`
	ActionSuffix string        `json:"action_suffix"`
	RequiredAAL  int           `json:"required_aal"`
	MaxAuthAge   time.Duration `json:"max_auth_age"`
}

func (p *StepUpPolicy) UnmarshalJSON(data []byte) error {
	var raw struct {
		ActionPrefix string          `json:"action_prefix"`
		ActionSuffix string          `json:"action_suffix"`
		RequiredAAL  int             `json:"required_aal"`
		MaxAuthAge   json.RawMessage `json:"max_auth_age"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.ActionPrefix = raw.ActionPrefix
	p.ActionSuffix = raw.ActionSuffix
	p.RequiredAAL = raw.RequiredAAL

	if len(raw.MaxAuthAge) == 0 || string(raw.MaxAuthAge) == "null" {
		p.MaxAuthAge = 0
		return nil
	}
	var maxAgeString string
	if err := json.Unmarshal(raw.MaxAuthAge, &maxAgeString); err == nil {
		d, parseErr := time.ParseDuration(strings.TrimSpace(maxAgeString))
		if parseErr != nil {
			return fmt.Errorf("invalid max_auth_age %q: %w", maxAgeString, parseErr)
		}
		p.MaxAuthAge = d
		return nil
	}
	var ns int64
	if err := json.Unmarshal(raw.MaxAuthAge, &ns); err == nil {
		p.MaxAuthAge = time.Duration(ns)
		return nil
	}
	return errors.New("max_auth_age must be duration string or integer nanoseconds")
}

type DecisionCacheBackend interface {
	Get(DecisionRequest) (DecisionResponse, bool)
	Set(DecisionRequest, DecisionResponse)
	Clear()
	Healthy(context.Context) error
}

type PolicyEngine struct {
	store   store.PolicyStore
	auditor *observability.AuditLogger
	logger  *slog.Logger
	opts    Options
	cache   DecisionCacheBackend
}

func NewEngine(store store.PolicyStore, auditor *observability.AuditLogger, logger *slog.Logger, opts *Options) *PolicyEngine {
	effective := Options{
		EnableOwnershipCheck: true,
		StepUpMaxAge:         30 * time.Minute,
		StepUpAAL:            2,
	}
	if opts != nil {
		effective.EnableOwnershipCheck = opts.EnableOwnershipCheck
		if opts.StepUpMaxAge > 0 {
			effective.StepUpMaxAge = opts.StepUpMaxAge
		}
		if opts.StepUpAAL > 0 {
			effective.StepUpAAL = opts.StepUpAAL
		}
		if opts.DecisionCacheTTL > 0 {
			effective.DecisionCacheTTL = opts.DecisionCacheTTL
		}
		if opts.Cache != nil {
			effective.Cache = opts.Cache
		}
		if len(opts.StepUpPolicies) > 0 {
			effective.StepUpPolicies = opts.StepUpPolicies
		}
		if len(opts.ContextPolicies) > 0 {
			effective.ContextPolicies = append([]ContextPolicy(nil), opts.ContextPolicies...)
		}
	}
	if len(effective.StepUpPolicies) == 0 {
		effective.StepUpPolicies = defaultStepUpPolicies(effective.StepUpMaxAge, effective.StepUpAAL)
	}
	if logger == nil {
		logger = slog.Default()
	}
	cacheBackend := effective.Cache
	if cacheBackend == nil && effective.DecisionCacheTTL > 0 {
		cacheBackend = NewDecisionCache(effective.DecisionCacheTTL)
	}
	return &PolicyEngine{
		store:   store,
		auditor: auditor,
		logger:  logger,
		opts:    effective,
		cache:   cacheBackend,
	}
}

func (e *PolicyEngine) Decide(ctx context.Context, req DecisionRequest) (DecisionResponse, error) {
	if e.store == nil {
		return DecisionResponse{}, ErrStoreUnavailable
	}
	requiredAAL, stepUpMaxAge := e.stepUpRequirement(req.Action)

	if req.Resource.TenantID != "" && req.Subject.TenantID != "" && req.Resource.TenantID != req.Subject.TenantID {
		resp := DecisionResponse{Allow: false, Reason: "tenant_mismatch"}
		e.recordAudit(ctx, req, resp)
		observability.DecisionsDeny.Add(1)
		observability.DecisionsTotal.Add(1)
		return resp, nil
	}

	hasContextPolicy := e.actionHasContextPolicy(req.Action)
	if e.cache != nil && requiredAAL == 0 && !hasContextPolicy {
		if cached, ok := e.cache.Get(req); ok {
			observability.CacheHits.Add(1)
			e.recordAudit(ctx, req, cached)
			observability.DecisionsAllow.Add(1)
			observability.DecisionsTotal.Add(1)
			return cached, nil
		}
		observability.CacheMisses.Add(1)
	}

	perms, err := e.store.GetUserPermissions(ctx, req.Subject.UserID, req.Subject.TenantID)
	if err != nil {
		return DecisionResponse{}, err
	}

	allowed, reason := evaluateRBAC(perms, req.Action)
	if !allowed && e.opts.EnableOwnershipCheck {
		if ownerAllowed, ownerReason := evaluateOwnership(req); ownerAllowed {
			allowed = true
			reason = ownerReason
		}
	}

	if allowed {
		if requiredAAL > 0 {
			if req.Subject.AAL < requiredAAL {
				observability.DecisionsStepUp.Add(1)
				observability.DecisionsDeny.Add(1)
				observability.DecisionsTotal.Add(1)
				resp := DecisionResponse{
					Allow:  false,
					Reason: "step_up_required",
					Obligations: map[string]interface{}{
						"require_aal": requiredAAL,
					},
				}
				e.recordAudit(ctx, req, resp)
				return resp, nil
			}
			maxAge := stepUpMaxAge
			if maxAge == 0 {
				maxAge = e.opts.StepUpMaxAge
			}
			if maxAge > 0 {
				if req.Subject.AuthTime.IsZero() || time.Since(req.Subject.AuthTime) > maxAge {
					observability.DecisionsStepUp.Add(1)
					observability.DecisionsDeny.Add(1)
					observability.DecisionsTotal.Add(1)
					resp := DecisionResponse{
						Allow:  false,
						Reason: "reauth_required",
						Obligations: map[string]interface{}{
							"require_aal":  requiredAAL,
							"max_auth_age": maxAge.String(),
						},
					}
					e.recordAudit(ctx, req, resp)
					return resp, nil
				}
			}
		}

		resp := DecisionResponse{Allow: true, Reason: reason}
		if cpReason, ok := e.applyContextPolicies(req); !ok {
			resp = DecisionResponse{Allow: false, Reason: cpReason}
			e.recordAudit(ctx, req, resp)
			observability.DecisionsDeny.Add(1)
			observability.DecisionsTotal.Add(1)
			return resp, nil
		}
		e.recordAudit(ctx, req, resp)
		observability.DecisionsAllow.Add(1)
		observability.DecisionsTotal.Add(1)
		if e.shouldCache(req, resp, requiredAAL) {
			e.cache.Set(req, resp)
		}
		return resp, nil
	}

	if reason == "" {
		reason = "rbac_denied"
	}
	resp := DecisionResponse{Allow: false, Reason: reason}
	e.recordAudit(ctx, req, resp)
	observability.DecisionsDeny.Add(1)
	observability.DecisionsTotal.Add(1)
	return resp, nil
}

func (e *PolicyEngine) recordAudit(ctx context.Context, req DecisionRequest, resp DecisionResponse) {
	if e.auditor == nil {
		return
	}
	entry := store.AuditLogEntry{
		SubjectUserID: req.Subject.UserID,
		TenantID:      req.Subject.TenantID,
		Action:        req.Action,
		ResourceType:  req.Resource.Type,
		ResourceID:    req.Resource.ID,
		Allow:         resp.Allow,
		Reason:        resp.Reason,
		IP:            req.Context.IP,
	}
	e.auditor.RecordDecision(ctx, entry)
}

func (e *PolicyEngine) stepUpRequirement(action string) (int, time.Duration) {
	action = strings.ToLower(strings.TrimSpace(action))
	required := 0
	var maxAge time.Duration
	for _, policy := range e.opts.StepUpPolicies {
		if matchesStepUpPolicy(action, policy) {
			if policy.RequiredAAL > required {
				required = policy.RequiredAAL
				maxAge = policy.MaxAuthAge
			} else if policy.RequiredAAL == required && policy.MaxAuthAge > maxAge {
				maxAge = policy.MaxAuthAge
			}
		}
	}
	return required, maxAge
}

func matchesStepUpPolicy(action string, policy StepUpPolicy) bool {
	if policy.ActionPrefix != "" && strings.HasPrefix(action, policy.ActionPrefix) {
		return true
	}
	if policy.ActionSuffix != "" && strings.HasSuffix(action, policy.ActionSuffix) {
		return true
	}
	return false
}

func defaultStepUpPolicies(maxAge time.Duration, aal int) []StepUpPolicy {
	return []StepUpPolicy{
		{ActionPrefix: "admin:", RequiredAAL: aal, MaxAuthAge: maxAge},
		{ActionSuffix: ":delete", RequiredAAL: aal, MaxAuthAge: maxAge},
	}
}

func (e *PolicyEngine) shouldCache(req DecisionRequest, resp DecisionResponse, requiredAAL int) bool {
	if e.cache == nil || requiredAAL > 0 {
		return false
	}
	if e.actionHasContextPolicy(req.Action) {
		return false
	}
	if !resp.Allow || len(resp.Obligations) > 0 {
		return false
	}
	if req.Resource.OwnerID != "" {
		return false
	}
	return strings.HasPrefix(resp.Reason, "rbac:")
}

func (e *PolicyEngine) applyContextPolicies(req DecisionRequest) (string, bool) {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	for _, p := range e.opts.ContextPolicies {
		if !p.matches(action) {
			continue
		}
		if p.allowed(req.Context) {
			continue
		}
		reason := "context_denied"
		if len(p.Obligations) > 0 {
			return reason, false
		}
		return reason, false
	}
	return "", true
}

func (e *PolicyEngine) actionHasContextPolicy(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return false
	}
	for _, p := range e.opts.ContextPolicies {
		if p.matches(action) {
			return true
		}
	}
	return false
}

// NoopEngine is a fallback engine that denies by default until a real policy
// backend is configured.
type NoopEngine struct {
	logger *slog.Logger
}

func NewNoopEngine(logger *slog.Logger) *NoopEngine {
	return &NoopEngine{logger: logger}
}

func (e *NoopEngine) Decide(ctx context.Context, req DecisionRequest) (DecisionResponse, error) {
	if e.logger != nil {
		e.logger.WarnContext(ctx, "authorization engine not configured; denying request",
			"action", req.Action,
			"tenant_id", req.Subject.TenantID,
			"user_id", req.Subject.UserID)
	}
	return DecisionResponse{
		Allow:  false,
		Reason: "engine_not_configured",
	}, nil
}
