package authz

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type ContextPolicy struct {
	ActionPrefix string         `json:"action_prefix"`
	ActionSuffix string         `json:"action_suffix"`
	AllowCIDRs   []string       `json:"allow_cidrs"`
	StartHour    int            `json:"start_hour"` // 0-23 inclusive
	EndHour      int            `json:"end_hour"`   // 0-23 inclusive
	Obligations  map[string]any `json:"obligations"`

	nets         []*net.IPNet
	hasStartHour bool `json:"-"`
	hasEndHour   bool `json:"-"`
}

type PolicyFile struct {
	ContextPolicies []ContextPolicy `json:"context_policies"`
	StepUpPolicies  []StepUpPolicy  `json:"step_up_policies"`
}

func LoadPolicyFile(path string) (*PolicyFile, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf PolicyFile
	if err := json.Unmarshal(body, &pf); err != nil {
		return nil, err
	}
	for i := range pf.ContextPolicies {
		if err := pf.ContextPolicies[i].normalize(); err != nil {
			return nil, fmt.Errorf("context policy %d: %w", i, err)
		}
	}
	for i := range pf.StepUpPolicies {
		pf.StepUpPolicies[i].ActionPrefix = strings.ToLower(strings.TrimSpace(pf.StepUpPolicies[i].ActionPrefix))
		pf.StepUpPolicies[i].ActionSuffix = strings.ToLower(strings.TrimSpace(pf.StepUpPolicies[i].ActionSuffix))
	}
	if err := pf.validate(); err != nil {
		return nil, err
	}
	return &pf, nil
}

func (p *ContextPolicy) UnmarshalJSON(data []byte) error {
	type contextPolicyAlias ContextPolicy
	var alias contextPolicyAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*p = ContextPolicy(alias)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, p.hasStartHour = raw["start_hour"]
	_, p.hasEndHour = raw["end_hour"]
	return nil
}

func (p *ContextPolicy) normalize() error {
	p.ActionPrefix = strings.ToLower(strings.TrimSpace(p.ActionPrefix))
	p.ActionSuffix = strings.ToLower(strings.TrimSpace(p.ActionSuffix))
	for i, cidr := range p.AllowCIDRs {
		parsed := strings.TrimSpace(cidr)
		if parsed == "" {
			continue
		}
		_, n, err := net.ParseCIDR(parsed)
		if err != nil {
			return fmt.Errorf("invalid allow_cidrs[%d]=%q", i, parsed)
		}
		p.nets = append(p.nets, n)
	}
	return nil
}

func (pf *PolicyFile) validate() error {
	for i, p := range pf.ContextPolicies {
		if p.hasStartHour != p.hasEndHour {
			return fmt.Errorf("context policy %d: start_hour and end_hour must be provided together", i)
		}
		if len(p.Obligations) > 0 {
			return fmt.Errorf("context policy %d: obligations are not supported", i)
		}
		hasHourWindow := p.hasStartHour || p.hasEndHour || p.StartHour != 0 || p.EndHour != 0
		if !hasHourWindow {
			continue
		}
		if p.StartHour < 0 || p.StartHour > 23 {
			return fmt.Errorf("context policy %d: start_hour must be between 0 and 23", i)
		}
		if p.EndHour < 0 || p.EndHour > 23 {
			return fmt.Errorf("context policy %d: end_hour must be between 0 and 23", i)
		}
	}
	for i, p := range pf.StepUpPolicies {
		if p.ActionPrefix == "" && p.ActionSuffix == "" {
			return fmt.Errorf("step-up policy %d: action_prefix or action_suffix is required", i)
		}
		if p.RequiredAAL <= 0 {
			return fmt.Errorf("step-up policy %d: required_aal must be > 0", i)
		}
		if p.MaxAuthAge < 0 {
			return fmt.Errorf("step-up policy %d: max_auth_age cannot be negative", i)
		}
	}
	return nil
}

func (p *ContextPolicy) matches(action string) bool {
	if p.ActionPrefix != "" && strings.HasPrefix(action, p.ActionPrefix) {
		return true
	}
	if p.ActionSuffix != "" && strings.HasSuffix(action, p.ActionSuffix) {
		return true
	}
	return false
}

func (p *ContextPolicy) allowed(ctxInfo ContextInfo) bool {
	if len(p.nets) > 0 {
		if strings.TrimSpace(ctxInfo.IP) == "" {
			// Fail-close when CIDR restriction exists but caller context has no IP.
			return false
		}
		ip := net.ParseIP(ctxInfo.IP)
		if ip == nil {
			return false
		}
		ok := false
		for _, n := range p.nets {
			if n.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	hasHourWindow := p.hasStartHour || p.hasEndHour || p.StartHour != 0 || p.EndHour != 0
	if hasHourWindow {
		now := time.Now().UTC()
		h := now.Hour()
		if p.StartHour <= p.EndHour {
			if h < p.StartHour || h > p.EndHour {
				return false
			}
		} else { // overnight window
			if h > p.EndHour && h < p.StartHour {
				return false
			}
		}
	}
	return true
}
