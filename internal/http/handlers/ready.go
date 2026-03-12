package handlers

import (
	"context"
	"net/http"
	"time"
)

type Pinger interface {
	PingContext(ctx context.Context) error
}

type ReadinessHandler struct {
	DB    Pinger
	Cache CacheHealth
}

type CacheHealth interface {
	Healthy(ctx context.Context) error
}

type MultiCacheHealth []CacheHealth

func (m MultiCacheHealth) Healthy(ctx context.Context) error {
	for _, c := range m {
		if c == nil {
			continue
		}
		if err := c.Healthy(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (h ReadinessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if h.DB != nil {
		if err := h.DB.PingContext(ctx); err != nil {
			respondError(w, http.StatusServiceUnavailable, "db not ready")
			return
		}
	}

	if h.Cache != nil {
		if err := h.Cache.Healthy(ctx); err != nil {
			respondError(w, http.StatusServiceUnavailable, "cache not ready")
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
