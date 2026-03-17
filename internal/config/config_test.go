package config

import "testing"

func TestValidateRejectsRemoteAuditHTTPByDefault(t *testing.T) {
	cfg := Config{
		AuditBaseURL:       "http://audit:8080",
		AuditInternalToken: "secret",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected remote http audit url to be rejected without explicit opt-in")
	}

	cfg.AuditAllowInsecure = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected explicit opt-in to allow remote http, got %v", err)
	}
}

func TestValidateRejectsRemoteSocialHTTPByDefault(t *testing.T) {
	cfg := Config{
		SocialBaseURL:       "http://social:8080",
		SocialInternalToken: "secret",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected remote http social url to be rejected without explicit opt-in")
	}

	cfg.SocialAllowInsecure = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected explicit opt-in to allow remote http, got %v", err)
	}
}
