package cache

import (
	"context"
	"sync"
	"time"

	"github.com/LCGant/role-pdp/internal/store"
)

const defaultPermissionCacheMaxEntries = 10000

// PermissionCache wraps a PolicyStore caching user permissions per tenant with a TTL.
// Cache entries are scoped by (user_id, tenant_id) to avoid cross-tenant leakage.
type PermissionCache struct {
	inner      store.PolicyStore
	ttl        time.Duration
	maxEntries int

	mu    sync.Mutex
	items map[string]cachedPerms
}

type cachedPerms struct {
	perms    []string
	deadline time.Time
}

func New(inner store.PolicyStore, ttl time.Duration) *PermissionCache {
	return &PermissionCache{
		inner:      inner,
		ttl:        ttl,
		maxEntries: defaultPermissionCacheMaxEntries,
		items:      make(map[string]cachedPerms),
	}
}

func (c *PermissionCache) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	if c == nil {
		return nil, nil
	}
	if c.ttl <= 0 {
		return c.inner.GetUserPermissions(ctx, userID, tenantID)
	}
	if key := cacheKey(userID, tenantID); key != "" {
		if perms, ok := c.lookup(key); ok {
			return perms, nil
		}
	}

	perms, err := c.inner.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	if key := cacheKey(userID, tenantID); key != "" {
		c.save(key, perms)
	}
	return perms, nil
}

func (c *PermissionCache) LogDecision(ctx context.Context, entry store.AuditLogEntry) error {
	return c.inner.LogDecision(ctx, entry)
}

func (c *PermissionCache) Close() error {
	return c.inner.Close()
}

func (c *PermissionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]cachedPerms)
}

func (c *PermissionCache) Healthy(ctx context.Context) error {
	return nil
}

func (c *PermissionCache) lookup(key string) ([]string, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok || now.After(entry.deadline) {
		if ok {
			delete(c.items, key)
		}
		return nil, false
	}
	return append([]string(nil), entry.perms...), true
}

func (c *PermissionCache) save(key string, perms []string) {
	if c.ttl <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeeded(now, key)
	c.items[key] = cachedPerms{
		perms:    append([]string(nil), perms...),
		deadline: now.Add(c.ttl),
	}
}

func (c *PermissionCache) evictIfNeeded(now time.Time, incomingKey string) {
	if c.maxEntries <= 0 {
		return
	}
	if _, exists := c.items[incomingKey]; exists {
		return
	}
	if len(c.items) < c.maxEntries {
		return
	}

	for k, item := range c.items {
		if now.After(item.deadline) {
			delete(c.items, k)
		}
	}
	if len(c.items) < c.maxEntries {
		return
	}

	oldestKey := ""
	var oldestDeadline time.Time
	for k, item := range c.items {
		if oldestKey == "" || item.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = item.deadline
		}
	}
	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}

func cacheKey(userID, tenantID string) string {
	if userID == "" || tenantID == "" {
		return ""
	}
	return tenantID + ":" + userID
}
