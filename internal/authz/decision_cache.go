package authz

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

const defaultDecisionCacheMaxEntries = 10000

// DecisionCache stores allow decisions for RBAC-only outcomes to avoid
// recalculating decisions with identical inputs. Ownership and step-up
// decisions are not cached to prevent stale or poisoned results.
type DecisionCache struct {
	ttl        time.Duration
	maxEntries int
	mu         sync.Mutex
	entries    map[string]cachedDecision
}

type cachedDecision struct {
	resp     DecisionResponse
	deadline time.Time
}

func NewDecisionCache(ttl time.Duration) *DecisionCache {
	if ttl <= 0 {
		return nil
	}
	return &DecisionCache{
		ttl:        ttl,
		maxEntries: defaultDecisionCacheMaxEntries,
		entries:    make(map[string]cachedDecision),
	}
}

func (c *DecisionCache) Get(req DecisionRequest) (DecisionResponse, bool) {
	if c == nil {
		return DecisionResponse{}, false
	}
	key := decisionCacheKey(req)
	if key == "" {
		return DecisionResponse{}, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.After(entry.deadline) {
		if ok {
			delete(c.entries, key)
		}
		return DecisionResponse{}, false
	}
	return entry.resp, true
}

func (c *DecisionCache) Set(req DecisionRequest, resp DecisionResponse) {
	if c == nil || c.ttl <= 0 {
		return
	}
	key := decisionCacheKey(req)
	if key == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeeded(now, key)
	c.entries[key] = cachedDecision{
		resp:     resp,
		deadline: now.Add(c.ttl),
	}
}

func (c *DecisionCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cachedDecision)
}

func (c *DecisionCache) Healthy(ctx context.Context) error {
	return nil
}

func (c *DecisionCache) evictIfNeeded(now time.Time, incomingKey string) {
	if c.maxEntries <= 0 {
		return
	}
	if _, exists := c.entries[incomingKey]; exists {
		return
	}
	if len(c.entries) < c.maxEntries {
		return
	}

	for k, entry := range c.entries {
		if now.After(entry.deadline) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxEntries {
		return
	}

	oldestKey := ""
	var oldestDeadline time.Time
	for k, entry := range c.entries {
		if oldestKey == "" || entry.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = entry.deadline
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func decisionCacheKey(req DecisionRequest) string {
	req.Normalize()
	if req.Subject.UserID == "" || req.Subject.TenantID == "" || req.Action == "" || req.Resource.Type == "" {
		return ""
	}
	id := req.Resource.ID
	if strings.TrimSpace(id) == "" {
		id = "*"
	}
	resourceTenant := req.Resource.TenantID
	if strings.TrimSpace(resourceTenant) == "" {
		resourceTenant = req.Subject.TenantID
	}
	return strings.Join([]string{
		strings.ToLower(req.Subject.TenantID),
		strings.ToLower(req.Subject.UserID),
		strings.ToLower(req.Subject.ActorID),
		strings.ToLower(req.Subject.ActorType),
		strings.ToLower(req.Action),
		strings.ToLower(req.Resource.Type),
		strings.ToLower(resourceTenant),
		strings.ToLower(id),
	}, "|")
}

func encodeDecisionResponse(resp DecisionResponse) ([]byte, error) {
	return json.Marshal(resp)
}

func decodeDecisionResponse(data []byte) (DecisionResponse, error) {
	var resp DecisionResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}
