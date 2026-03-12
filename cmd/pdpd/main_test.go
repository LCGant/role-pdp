package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LCGant/role-pdp/internal/config"
)

func TestBuildPoliciesReturnsErrorForInvalidPolicyFile(t *testing.T) {
	cfg := config.Config{
		StepUpAAL:    2,
		StepUpMaxAge: 30 * time.Minute,
		PolicyFile:   filepath.Join("testdata", "invalid_policy.json"),
	}

	_, _, err := buildPolicies(cfg)
	if err == nil {
		t.Fatalf("expected error for invalid policy file")
	}
}
