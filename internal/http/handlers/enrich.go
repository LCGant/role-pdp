package handlers

import (
	"context"
	"errors"
	"strings"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/social"
)

type RequestEnricher interface {
	Enrich(context.Context, *authz.DecisionRequest) error
}

func enrichDecisionRequest(ctx context.Context, enricher RequestEnricher, req *authz.DecisionRequest) (*authz.DecisionResponse, error) {
	if req != nil && enricher == nil {
		resourceType := strings.ToLower(strings.TrimSpace(req.Resource.Type))
		if resourceType == "profiles" || resourceType == "playlists" || resourceType == "events" {
			return &authz.DecisionResponse{Allow: false, Reason: "social_context_unavailable"}, nil
		}
	}
	if enricher == nil {
		return nil, nil
	}
	if err := enricher.Enrich(ctx, req); err != nil {
		if errors.Is(err, social.ErrNotFound) {
			return &authz.DecisionResponse{Allow: false, Reason: "resource_not_found"}, nil
		}
		return nil, err
	}
	return nil, nil
}
