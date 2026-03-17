package social

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/config"
)

var ErrNotFound = errors.New("social resource not found")

type Client struct {
	baseURL       string
	internalToken string
	timeout       time.Duration
	httpClient    *http.Client
}

type profileAuthzContext struct {
	Profile struct {
		ActorID    string `json:"actor_id"`
		ActorType  string `json:"actor_type"`
		Visibility string `json:"visibility"`
	} `json:"profile"`
	ViewerBlocked bool `json:"viewer_blocked"`
	ViewerFollows bool `json:"viewer_follows"`
	ViewerFriend  bool `json:"viewer_friend"`
}

func NewClient(cfg config.Config) *Client {
	if strings.TrimSpace(cfg.SocialBaseURL) == "" || strings.TrimSpace(cfg.SocialInternalToken) == "" {
		return nil
	}
	timeout := cfg.SocialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL:       strings.TrimRight(cfg.SocialBaseURL, "/"),
		internalToken: cfg.SocialInternalToken,
		timeout:       timeout,
		httpClient:    &http.Client{Timeout: timeout},
	}
}

func (c *Client) Enrich(ctx context.Context, req *authz.DecisionRequest) error {
	if c == nil || req == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(req.Resource.Type), "profiles") {
		return nil
	}
	if strings.TrimSpace(req.Resource.ID) == "" {
		return nil
	}

	enriched, err := c.fetchProfileAuthzContext(ctx, req)
	if err != nil {
		return err
	}

	req.Resource.OwnerActorID = strings.TrimSpace(enriched.Profile.ActorID)
	req.Resource.OwnerActorType = strings.TrimSpace(strings.ToLower(enriched.Profile.ActorType))
	if req.Resource.OwnerActorID != "" {
		req.Resource.OwnerID = req.Resource.OwnerActorID
	}
	req.Resource.Visibility = strings.TrimSpace(strings.ToLower(enriched.Profile.Visibility))
	req.Relationships = authz.RelationshipInfo{
		Blocked:   enriched.ViewerBlocked,
		Following: enriched.ViewerFollows,
		Friend:    enriched.ViewerFriend,
	}
	return nil
}

func (c *Client) fetchProfileAuthzContext(ctx context.Context, req *authz.DecisionRequest) (profileAuthzContext, error) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := c.baseURL + "/internal/profiles/" + url.PathEscape(strings.TrimSpace(req.Resource.ID)) + "/authz-context"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return profileAuthzContext{}, err
	}
	httpReq.Header.Set("X-Internal-Token", c.internalToken)
	httpReq.Header.Set("X-User-Id", req.Subject.UserID)
	if strings.TrimSpace(req.Subject.ActorID) != "" {
		httpReq.Header.Set("X-Actor-Id", req.Subject.ActorID)
	}
	if strings.TrimSpace(req.Subject.ActorType) != "" {
		httpReq.Header.Set("X-Actor-Type", req.Subject.ActorType)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return profileAuthzContext{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return profileAuthzContext{}, ErrNotFound
	default:
		return profileAuthzContext{}, fmt.Errorf("social service returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return profileAuthzContext{}, err
	}
	if len(body) > 1<<20 {
		return profileAuthzContext{}, errors.New("social response too large")
	}
	var out profileAuthzContext
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return profileAuthzContext{}, err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return profileAuthzContext{}, err
	}
	return out, nil
}
