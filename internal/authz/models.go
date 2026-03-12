package authz

import "time"

type Subject struct {
	UserID   string    `json:"user_id"`
	TenantID string    `json:"tenant_id"`
	AAL      int       `json:"aal"`
	AuthTime time.Time `json:"auth_time"`
}

type Resource struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	OwnerID  string `json:"owner_id"`
}

type ContextInfo struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type DecisionRequest struct {
	Subject  Subject     `json:"subject"`
	Action   string      `json:"action"`
	Resource Resource    `json:"resource"`
	Context  ContextInfo `json:"context"`
}

type DecisionResponse struct {
	Allow       bool                   `json:"allow"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
}
