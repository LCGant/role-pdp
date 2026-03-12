package handlers

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

func internalTokenMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token == "" {
				respondError(w, http.StatusServiceUnavailable, "internal token not configured")
				return
			}
			header := r.Header.Get("X-Internal-Token")
			if header == "" || len(header) != len(token) || subtle.ConstantTimeCompare([]byte(header), []byte(token)) != 1 {
				respondError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func metricsTokenMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := net.ParseIP(requestHost(r.RemoteAddr)); ip != nil && ip.IsLoopback() {
				next.ServeHTTP(w, r)
				return
			}
			header := r.Header.Get("X-Metrics-Token")
			if token == "" || header == "" || len(header) != len(token) || subtle.ConstantTimeCompare([]byte(header), []byte(token)) != 1 {
				respondError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requestHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.Trim(remoteAddr, "[]")
}
