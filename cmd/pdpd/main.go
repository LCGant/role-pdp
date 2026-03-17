package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LCGant/role-pdp/internal/audit"
	"github.com/LCGant/role-pdp/internal/authz"
	"github.com/LCGant/role-pdp/internal/config"
	"github.com/LCGant/role-pdp/internal/http/handlers"
	"github.com/LCGant/role-pdp/internal/observability"
	"github.com/LCGant/role-pdp/internal/social"
	"github.com/LCGant/role-pdp/internal/store/cache"
	"github.com/LCGant/role-pdp/internal/store/postgres"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.DBURL == "" {
		logger.Error("PDP_DB_URL (or DATABASE_URL) must be set")
		os.Exit(1)
	}
	if cfg.InternalToken == "" {
		logger.Error("PDP_INTERNAL_TOKEN must be set")
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		logger.Error("PDP_TLS_CERT_FILE and PDP_TLS_KEY_FILE must both be set when TLS is enabled")
		os.Exit(1)
	}

	dbCtx, cancelDB := context.WithTimeout(ctx, 10*time.Second)
	defer cancelDB()
	policyStore, err := postgres.New(dbCtx, cfg.DBURL)
	if err != nil {
		logger.Error("failed to connect to postgres", "error", err)
		os.Exit(1)
	}
	defer policyStore.Close()

	cachedStore := cache.New(policyStore, cfg.CacheTTL)
	auditor := &observability.AuditLogger{Sink: cachedStore, Remote: audit.NewClient(cfg), Logger: logger}
	decisionCache, cacheHealth := buildDecisionCache(cfg, logger)
	stepUpPolicies, ctxPolicies, err := buildPolicies(cfg)
	if err != nil {
		logger.Error("failed to build policies", "error", err)
		os.Exit(1)
	}
	engine := authz.NewEngine(cachedStore, auditor, logger, &authz.Options{
		EnableOwnershipCheck: cfg.EnableOwnership,
		StepUpMaxAge:         cfg.StepUpMaxAge,
		StepUpAAL:            cfg.StepUpAAL,
		StepUpPolicies:       stepUpPolicies,
		DecisionCacheTTL:     cfg.DecisionCacheTTL,
		Cache:                decisionCache,
		ContextPolicies:      ctxPolicies,
	})
	rateLimiter := handlers.NewRateLimiter(cfg.RateLimitPerMin, cfg.RateLimitBurst)
	socialClient := social.NewClient(cfg)

	router := handlers.NewRouter(handlers.RouterParams{
		Logger:         logger,
		Engine:         engine,
		EnableMetrics:  cfg.EnableMetrics,
		RateLimiter:    rateLimiter,
		Readiness:      handlers.ReadinessHandler{DB: policyStore, Cache: handlers.MultiCacheHealth{cachedStore, cacheHealth}},
		AdminToken:     cfg.AdminToken,
		InternalToken:  cfg.InternalToken,
		MetricsToken:   cfg.MetricsToken,
		Caches:         []handlers.CacheClearer{cachedStore, decisionCache},
		AdminStore:     handlers.AdminAdapter{Inner: policyStore},
		ClientIDHeader: cfg.ClientIDHeader,
		Enricher:       socialClient,
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	go func() {
		logger.Info("starting PDP server", "addr", cfg.HTTPAddr, "env", cfg.Env)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			tlsCfg, err := buildTLSConfig(cfg)
			if err != nil {
				logger.Error("invalid TLS config", "error", err)
				stop()
				return
			}
			server.TLSConfig = tlsCfg
			if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Error("server failed", "error", err)
				stop()
			}
			return
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	logger.Info("shutting down PDP server")
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

func buildPolicies(cfg config.Config) ([]authz.StepUpPolicy, []authz.ContextPolicy, error) {
	var policies []authz.StepUpPolicy
	for _, raw := range cfg.StepUpActions {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			continue
		}
		if strings.HasSuffix(raw, "*") {
			prefix := strings.TrimSuffix(raw, "*")
			policies = append(policies, authz.StepUpPolicy{
				ActionPrefix: prefix,
				RequiredAAL:  cfg.StepUpAAL,
				MaxAuthAge:   cfg.StepUpMaxAge,
			})
			continue
		}
		if strings.HasPrefix(raw, "*") {
			suffix := strings.TrimPrefix(raw, "*")
			policies = append(policies, authz.StepUpPolicy{
				ActionSuffix: suffix,
				RequiredAAL:  cfg.StepUpAAL,
				MaxAuthAge:   cfg.StepUpMaxAge,
			})
			continue
		}
		policies = append(policies, authz.StepUpPolicy{
			ActionSuffix: raw,
			RequiredAAL:  cfg.StepUpAAL,
			MaxAuthAge:   cfg.StepUpMaxAge,
		})
	}
	if cfg.PolicyFile != "" {
		if pf, err := authz.LoadPolicyFile(cfg.PolicyFile); err != nil {
			return nil, nil, err
		} else {
			if len(pf.StepUpPolicies) > 0 {
				policies = append(policies, pf.StepUpPolicies...)
			}
			return policies, pf.ContextPolicies, nil
		}
	}
	return policies, nil, nil
}

func buildDecisionCache(cfg config.Config, logger *slog.Logger) (authz.DecisionCacheBackend, handlers.CacheHealth) {
	if cfg.RedisURL != "" {
		rc, err := authz.NewRedisDecisionCache(cfg.RedisURL, cfg.DecisionCacheTTL)
		if err != nil {
			logger.Error("failed to init redis decision cache, falling back to memory", "error", err)
		} else {
			return rc, rc
		}
	}
	dc := authz.NewDecisionCache(cfg.DecisionCacheTTL)
	return dc, dc
}

func buildTLSConfig(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.RequireClientCA && cfg.TLSClientCAFile == "" {
		return nil, errors.New("PDP_REQUIRE_CLIENT_CA=true requires PDP_TLS_CLIENT_CA_FILE")
	}
	if cfg.TLSClientCAFile != "" {
		caCert, err := os.ReadFile(cfg.TLSClientCAFile)
		if err != nil {
			return nil, err
		}
		cp := x509.NewCertPool()
		if ok := cp.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("invalid client CA file")
		}
		tlsCfg.ClientCAs = cp
		if cfg.RequireClientCA {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return tlsCfg, nil
}
