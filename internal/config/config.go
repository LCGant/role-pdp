package config

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration values loaded from environment variables.
// Defaults keep the service usable in local development while encouraging
// explicit configuration in production deployments.
type Config struct {
	HTTPAddr            string
	DBURL               string
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	MaxHeaderBytes      int
	LogLevel            slog.Level
	EnableMetrics       bool
	Env                 string
	EnableOwnership     bool
	StepUpMaxAge        time.Duration
	CacheTTL            time.Duration
	StepUpActions       []string
	StepUpAAL           int
	DecisionCacheTTL    time.Duration
	RateLimitPerMin     int
	RateLimitBurst      int
	TLSCertFile         string
	TLSKeyFile          string
	TLSClientCAFile     string
	RequireClientCA     bool
	AdminToken          string
	InternalToken       string
	MetricsToken        string
	PolicyFile          string
	RedisURL            string
	ClientIDHeader      string
	AuditBaseURL        string
	AuditInternalToken  string
	AuditSpoolDir       string
	AuditTimeout        time.Duration
	AuditAllowInsecure  bool
	SocialBaseURL       string
	SocialInternalToken string
	SocialTimeout       time.Duration
	SocialAllowInsecure bool
}

// Load reads configuration from environment variables, applying sane defaults
// when values are absent or malformed.
func Load() Config {
	return Config{
		HTTPAddr:            envString("PDP_HTTP_ADDR", ":8080"),
		DBURL:               chooseString(os.Getenv("PDP_DB_URL"), os.Getenv("DATABASE_URL")),
		ReadTimeout:         envDuration("PDP_READ_TIMEOUT", 5*time.Second),
		WriteTimeout:        envDuration("PDP_WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:         envDuration("PDP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:     envDuration("PDP_SHUTDOWN_TIMEOUT", 10*time.Second),
		MaxHeaderBytes:      envPositiveInt("PDP_MAX_HEADER_BYTES", 64*1024),
		LogLevel:            envLogLevel("PDP_LOG_LEVEL", slog.LevelInfo),
		EnableMetrics:       envBool("PDP_ENABLE_METRICS", true),
		EnableOwnership:     envBool("PDP_ENABLE_OWNERSHIP", true),
		StepUpMaxAge:        envDuration("PDP_STEPUP_MAX_AGE", 30*time.Minute),
		CacheTTL:            envDuration("PDP_CACHE_TTL", 0),
		StepUpActions:       envList("PDP_STEPUP_ACTIONS"),
		StepUpAAL:           envInt("PDP_STEPUP_AAL", 2),
		DecisionCacheTTL:    envDuration("PDP_DECISION_CACHE_TTL", 0),
		RateLimitPerMin:     envInt("PDP_RATE_LIMIT_PER_MIN", 120),
		RateLimitBurst:      envInt("PDP_RATE_LIMIT_BURST", 30),
		TLSCertFile:         envString("PDP_TLS_CERT_FILE", ""),
		TLSKeyFile:          envString("PDP_TLS_KEY_FILE", ""),
		TLSClientCAFile:     envString("PDP_TLS_CLIENT_CA_FILE", ""),
		RequireClientCA:     envBool("PDP_REQUIRE_CLIENT_CA", false),
		AdminToken:          envString("PDP_ADMIN_TOKEN", ""),
		InternalToken:       envString("PDP_INTERNAL_TOKEN", ""),
		MetricsToken:        envString("PDP_METRICS_TOKEN", ""),
		PolicyFile:          envString("PDP_POLICY_FILE", ""),
		RedisURL:            envString("PDP_REDIS_URL", ""),
		ClientIDHeader:      envString("PDP_CLIENT_ID_HEADER", ""),
		AuditBaseURL:        envString("AUDIT_BASE_URL", ""),
		AuditInternalToken:  envString("AUDIT_INTERNAL_TOKEN", ""),
		AuditSpoolDir:       envString("PDP_AUDIT_SPOOL_DIR", filepath.Join(os.TempDir(), "pdp-audit-spool")),
		AuditTimeout:        envDuration("AUDIT_TIMEOUT", 5*time.Second),
		AuditAllowInsecure:  envBool("AUDIT_ALLOW_INSECURE_HTTP", false),
		SocialBaseURL:       envString("SOCIAL_BASE_URL", ""),
		SocialInternalToken: envString("SOCIAL_INTERNAL_TOKEN", ""),
		SocialTimeout:       envDuration("SOCIAL_TIMEOUT", 5*time.Second),
		SocialAllowInsecure: envBool("SOCIAL_ALLOW_INSECURE_HTTP", false),
		Env:                 envString("PDP_ENV", "development"),
	}
}

func (c Config) Validate() error {
	if c.AuditBaseURL != "" && c.AuditInternalToken == "" {
		return errors.New("AUDIT_INTERNAL_TOKEN is required when AUDIT_BASE_URL is set")
	}
	if c.AuditBaseURL == "" && c.AuditInternalToken != "" {
		return errors.New("AUDIT_BASE_URL is required when AUDIT_INTERNAL_TOKEN is set")
	}
	if err := validateRemoteURL(c.AuditBaseURL, c.AuditAllowInsecure); err != nil {
		return err
	}
	if c.SocialBaseURL != "" && c.SocialInternalToken == "" {
		return errors.New("SOCIAL_INTERNAL_TOKEN is required when SOCIAL_BASE_URL is set")
	}
	if c.SocialBaseURL == "" && c.SocialInternalToken != "" {
		return errors.New("SOCIAL_BASE_URL is required when SOCIAL_INTERNAL_TOKEN is set")
	}
	if err := validateRemoteURL(c.SocialBaseURL, c.SocialAllowInsecure); err != nil {
		return err
	}
	return nil
}

func validateRemoteURL(raw string, allowInsecure bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("remote http requires explicit AUDIT_ALLOW_INSECURE_HTTP opt-in")
	default:
		return errors.New("unsupported audit url scheme")
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func chooseString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envDuration(key string, def time.Duration) time.Duration {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return v
}

func envLogLevel(key string, def slog.Level) slog.Level {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return def
	}
}

func envList(key string) []string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envInt(key string, def int) int {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func envPositiveInt(key string, def int) int {
	v := envInt(key, def)
	if v <= 0 {
		return def
	}
	return v
}
