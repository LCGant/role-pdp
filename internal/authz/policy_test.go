package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyFileRejectsInvalidCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"context_policies":[{"action_prefix":"admin:","allow_cidrs":["bad-cidr"]}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatalf("expected invalid CIDR error")
	}
}

func TestLoadPolicyFileRejectsInvalidStepUpPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"step_up_policies":[{"required_aal":0}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatalf("expected invalid step-up policy error")
	}
}

func TestLoadPolicyFileValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{
		"context_policies":[{"action_prefix":"admin:","allow_cidrs":["10.0.0.0/8"],"start_hour":8,"end_hour":19}],
		"step_up_policies":[{"action_prefix":"admin:","required_aal":2}]
	}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	pf, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pf.ContextPolicies) != 1 || len(pf.StepUpPolicies) != 1 {
		t.Fatalf("unexpected policy counts: %+v", pf)
	}
}

func TestLoadPolicyFileRejectsHalfHourWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"context_policies":[{"action_prefix":"admin:","start_hour":8}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatalf("expected error for half-defined hour window")
	}
}

func TestLoadPolicyFileRejectsUnsupportedContextObligations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"context_policies":[{"action_prefix":"admin:","obligations":{"require_reason":"ticket"}}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	if _, err := LoadPolicyFile(path); err == nil {
		t.Fatalf("expected unsupported obligations error")
	}
}

func TestLoadPolicyFileTracksExplicitMidnightWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := `{"context_policies":[{"action_prefix":"admin:","start_hour":0,"end_hour":0}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	pf, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pf.ContextPolicies) != 1 {
		t.Fatalf("expected exactly one context policy, got %d", len(pf.ContextPolicies))
	}
	p := pf.ContextPolicies[0]
	if !p.hasStartHour || !p.hasEndHour {
		t.Fatalf("expected explicit start/end hour flags, got start=%v end=%v", p.hasStartHour, p.hasEndHour)
	}
}

func TestContextPolicyAllowedFailsWhenCIDRConfiguredAndIPMissing(t *testing.T) {
	p := &ContextPolicy{
		AllowCIDRs: []string{"10.0.0.0/8"},
	}
	if err := p.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if p.allowed(ContextInfo{}) {
		t.Fatalf("expected deny when IP is missing with allow_cidrs configured")
	}
}

func TestContextPolicyAllowedRespectsCIDR(t *testing.T) {
	p := &ContextPolicy{
		AllowCIDRs: []string{"10.0.0.0/8"},
	}
	if err := p.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !p.allowed(ContextInfo{IP: "10.1.2.3"}) {
		t.Fatalf("expected allow for IP inside CIDR")
	}
	if p.allowed(ContextInfo{IP: "203.0.113.7"}) {
		t.Fatalf("expected deny for IP outside CIDR")
	}
}
