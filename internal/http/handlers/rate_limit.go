package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultPDPRateLimiterMaxEntries = 10000
	defaultPDPRateLimiterIdleTTL    = 10 * time.Minute
)

type RateLimiter struct {
	rate       float64
	burst      float64
	mu         sync.Mutex
	bucket     map[string]*tokenBucket
	maxEntries int
	idleTTL    time.Duration
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = perMinute
	}
	return &RateLimiter{
		rate:       float64(perMinute) / 60.0,
		burst:      float64(burst),
		bucket:     make(map[string]*tokenBucket),
		maxEntries: defaultPDPRateLimiterMaxEntries,
		idleTTL:    defaultPDPRateLimiterIdleTTL,
	}
}

func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bucket[key]
	if !ok {
		r.evictIfNeeded(now)
		b = &tokenBucket{tokens: r.burst, last: now}
		r.bucket[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.last = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func (r *RateLimiter) evictIfNeeded(now time.Time) {
	if r.maxEntries <= 0 || len(r.bucket) < r.maxEntries {
		return
	}
	if r.idleTTL > 0 {
		for k, b := range r.bucket {
			if now.Sub(b.last) > r.idleTTL {
				delete(r.bucket, k)
			}
		}
	}
	for len(r.bucket) >= r.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for k, b := range r.bucket {
			if oldestKey == "" || b.last.Before(oldest) {
				oldestKey = k
				oldest = b.last
			}
		}
		if oldestKey == "" {
			return
		}
		delete(r.bucket, oldestKey)
	}
}

func rateLimitKey(r *http.Request) string {
	return rateLimitKeyInternal(r, true)
}

func rateLimitKeyInternal(r *http.Request, allowInternalToken bool) string {
	if h := r.Context().Value(contextKey("clientIDHeader")); h != nil {
		if headerName, ok := h.(string); ok && headerName != "" {
			if client := strings.TrimSpace(r.Header.Get(headerName)); client != "" {
				return "client:" + client
			}
		}
	}
	if allowInternalToken {
		if token := r.Header.Get("X-Internal-Token"); token != "" {
			sum := sha256.Sum256([]byte(token))
			// Fingerprint only, never keep raw tokens in memory structures or logs.
			return "token:" + hex.EncodeToString(sum[:8])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return "ip:" + host
	}
	return "ip:" + r.RemoteAddr
}

func rateLimitAdminKey(r *http.Request) string {
	host := requestHost(r.RemoteAddr)
	if h := r.Context().Value(contextKey("clientIDHeader")); h != nil {
		if headerName, ok := h.(string); ok && headerName != "" {
			if client := strings.TrimSpace(r.Header.Get(headerName)); client != "" {
				return "admin_client:" + host + ":" + client
			}
		}
	}
	if client := strings.TrimSpace(r.Header.Get("X-Client-Id")); client != "" {
		return "admin_client:" + host + ":" + client
	}
	return "admin_ip:" + host
}

func rateLimitAdminPreAuthKey(r *http.Request) string {
	return "admin_preauth_ip:" + requestHost(r.RemoteAddr)
}
