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

type playlistAuthzContext struct {
	Playlist struct {
		OwnerActorID   string `json:"owner_actor_id"`
		OwnerActorType string `json:"owner_actor_type"`
		Visibility     string `json:"visibility"`
	} `json:"playlist"`
	ViewerBlocked      bool `json:"viewer_blocked"`
	ViewerFollows      bool `json:"viewer_follows"`
	ViewerFriend       bool `json:"viewer_friend"`
	ViewerShared       bool `json:"viewer_shared"`
	ViewerCollaborator bool `json:"viewer_collaborator"`
}

type postAuthzContext struct {
	Post struct {
		OwnerActorID   string `json:"owner_actor_id"`
		OwnerActorType string `json:"owner_actor_type"`
		Visibility     string `json:"visibility"`
	} `json:"post"`
	ViewerBlocked bool `json:"viewer_blocked"`
	ViewerFollows bool `json:"viewer_follows"`
	ViewerFriend  bool `json:"viewer_friend"`
}

type eventAuthzContext struct {
	Event struct {
		OwnerActorID   string `json:"owner_actor_id"`
		OwnerActorType string `json:"owner_actor_type"`
		Visibility     string `json:"visibility"`
	} `json:"event"`
	ViewerBlocked     bool `json:"viewer_blocked"`
	ViewerFollows     bool `json:"viewer_follows"`
	ViewerFriend      bool `json:"viewer_friend"`
	ViewerInvited     bool `json:"viewer_invited"`
	ViewerParticipant bool `json:"viewer_participant"`
	ViewerOrganizer   bool `json:"viewer_organizer"`
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
	resourceType := strings.ToLower(strings.TrimSpace(req.Resource.Type))
	if resourceType != "profiles" && resourceType != "posts" && resourceType != "playlists" && resourceType != "events" {
		return nil
	}
	if strings.TrimSpace(req.Resource.ID) == "" {
		return nil
	}

	switch resourceType {
	case "profiles":
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
	case "posts":
		enriched, err := c.fetchPostAuthzContext(ctx, req)
		if err != nil {
			return err
		}
		req.Resource.OwnerActorID = strings.TrimSpace(enriched.Post.OwnerActorID)
		req.Resource.OwnerActorType = strings.TrimSpace(strings.ToLower(enriched.Post.OwnerActorType))
		if req.Resource.OwnerActorID != "" {
			req.Resource.OwnerID = req.Resource.OwnerActorID
		}
		req.Resource.Visibility = strings.TrimSpace(strings.ToLower(enriched.Post.Visibility))
		req.Relationships = authz.RelationshipInfo{
			Blocked:   enriched.ViewerBlocked,
			Following: enriched.ViewerFollows,
			Friend:    enriched.ViewerFriend,
		}
	case "playlists":
		enriched, err := c.fetchPlaylistAuthzContext(ctx, req)
		if err != nil {
			return err
		}
		req.Resource.OwnerActorID = strings.TrimSpace(enriched.Playlist.OwnerActorID)
		req.Resource.OwnerActorType = strings.TrimSpace(strings.ToLower(enriched.Playlist.OwnerActorType))
		if req.Resource.OwnerActorID != "" {
			req.Resource.OwnerID = req.Resource.OwnerActorID
		}
		req.Resource.Visibility = strings.TrimSpace(strings.ToLower(enriched.Playlist.Visibility))
		req.Relationships = authz.RelationshipInfo{
			Blocked:      enriched.ViewerBlocked,
			Following:    enriched.ViewerFollows,
			Friend:       enriched.ViewerFriend,
			Shared:       enriched.ViewerShared,
			Collaborator: enriched.ViewerCollaborator,
		}
	case "events":
		enriched, err := c.fetchEventAuthzContext(ctx, req)
		if err != nil {
			return err
		}
		req.Resource.OwnerActorID = strings.TrimSpace(enriched.Event.OwnerActorID)
		req.Resource.OwnerActorType = strings.TrimSpace(strings.ToLower(enriched.Event.OwnerActorType))
		if req.Resource.OwnerActorID != "" {
			req.Resource.OwnerID = req.Resource.OwnerActorID
		}
		req.Resource.Visibility = strings.TrimSpace(strings.ToLower(enriched.Event.Visibility))
		req.Relationships = authz.RelationshipInfo{
			Blocked:     enriched.ViewerBlocked,
			Following:   enriched.ViewerFollows,
			Friend:      enriched.ViewerFriend,
			Invited:     enriched.ViewerInvited,
			Participant: enriched.ViewerParticipant || enriched.ViewerOrganizer,
		}
	}
	return nil
}

func (c *Client) fetchPostAuthzContext(ctx context.Context, req *authz.DecisionRequest) (postAuthzContext, error) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := c.baseURL + "/internal/posts/" + url.PathEscape(strings.TrimSpace(req.Resource.ID)) + "/authz-context"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return postAuthzContext{}, err
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
		return postAuthzContext{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return postAuthzContext{}, ErrNotFound
	default:
		return postAuthzContext{}, fmt.Errorf("social service returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return postAuthzContext{}, err
	}
	if len(body) > 1<<20 {
		return postAuthzContext{}, errors.New("social response too large")
	}
	var out postAuthzContext
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return postAuthzContext{}, err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return postAuthzContext{}, err
	}
	return out, nil
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

func (c *Client) fetchPlaylistAuthzContext(ctx context.Context, req *authz.DecisionRequest) (playlistAuthzContext, error) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := c.baseURL + "/internal/playlists/" + url.PathEscape(strings.TrimSpace(req.Resource.ID)) + "/authz-context"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return playlistAuthzContext{}, err
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
		return playlistAuthzContext{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return playlistAuthzContext{}, ErrNotFound
	default:
		return playlistAuthzContext{}, fmt.Errorf("social service returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return playlistAuthzContext{}, err
	}
	if len(body) > 1<<20 {
		return playlistAuthzContext{}, errors.New("social response too large")
	}
	var out playlistAuthzContext
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return playlistAuthzContext{}, err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return playlistAuthzContext{}, err
	}
	return out, nil
}

func (c *Client) fetchEventAuthzContext(ctx context.Context, req *authz.DecisionRequest) (eventAuthzContext, error) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := c.baseURL + "/internal/events/" + url.PathEscape(strings.TrimSpace(req.Resource.ID)) + "/authz-context"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return eventAuthzContext{}, err
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
		return eventAuthzContext{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return eventAuthzContext{}, ErrNotFound
	default:
		return eventAuthzContext{}, fmt.Errorf("social service returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return eventAuthzContext{}, err
	}
	if len(body) > 1<<20 {
		return eventAuthzContext{}, errors.New("social response too large")
	}
	var out eventAuthzContext
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return eventAuthzContext{}, err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return eventAuthzContext{}, err
	}
	return out, nil
}
