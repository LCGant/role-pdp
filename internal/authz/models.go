package authz

import (
	"strings"
	"time"
)

type Subject struct {
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	ActorID   string    `json:"actor_id,omitempty"`
	ActorType string    `json:"actor_type,omitempty"`
	AAL       int       `json:"aal"`
	AuthTime  time.Time `json:"auth_time"`
}

type Resource struct {
	Type           string `json:"type"`
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	OwnerID        string `json:"owner_id"`
	OwnerActorID   string `json:"owner_actor_id,omitempty"`
	OwnerActorType string `json:"owner_actor_type,omitempty"`
	Visibility     string `json:"visibility,omitempty"`
}

type ContextInfo struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type RelationshipInfo struct {
	Blocked      bool `json:"blocked,omitempty"`
	Following    bool `json:"following,omitempty"`
	Friend       bool `json:"friend,omitempty"`
	Shared       bool `json:"shared,omitempty"`
	Participant  bool `json:"participant,omitempty"`
	Invited      bool `json:"invited,omitempty"`
	Collaborator bool `json:"collaborator,omitempty"`
}

type DecisionRequest struct {
	Subject       Subject          `json:"subject"`
	Action        string           `json:"action"`
	Resource      Resource         `json:"resource"`
	Context       ContextInfo      `json:"context"`
	Relationships RelationshipInfo `json:"relationships,omitempty"`
}

type DecisionResponse struct {
	Allow       bool                   `json:"allow"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations map[string]interface{} `json:"obligations,omitempty"`
}

func (r *DecisionRequest) Normalize() {
	r.Action = strings.TrimSpace(r.Action)

	r.Subject.UserID = strings.TrimSpace(r.Subject.UserID)
	r.Subject.TenantID = strings.TrimSpace(r.Subject.TenantID)
	r.Subject.ActorID = strings.TrimSpace(r.Subject.ActorID)
	r.Subject.ActorType = strings.TrimSpace(strings.ToLower(r.Subject.ActorType))
	if r.Subject.ActorID == "" {
		r.Subject.ActorID = r.Subject.UserID
	}
	if r.Subject.ActorType == "" {
		r.Subject.ActorType = "person"
	}

	r.Resource.Type = strings.TrimSpace(r.Resource.Type)
	r.Resource.ID = strings.TrimSpace(r.Resource.ID)
	r.Resource.TenantID = strings.TrimSpace(r.Resource.TenantID)
	r.Resource.OwnerID = strings.TrimSpace(r.Resource.OwnerID)
	r.Resource.OwnerActorID = strings.TrimSpace(r.Resource.OwnerActorID)
	r.Resource.OwnerActorType = strings.TrimSpace(strings.ToLower(r.Resource.OwnerActorType))
	r.Resource.Visibility = strings.TrimSpace(strings.ToLower(r.Resource.Visibility))
	if r.Resource.OwnerActorID == "" && r.Resource.OwnerID != "" {
		r.Resource.OwnerActorID = r.Resource.OwnerID
	}
	if r.Resource.OwnerActorType == "" && r.Resource.OwnerActorID != "" {
		r.Resource.OwnerActorType = "person"
	}

	r.Context.IP = strings.TrimSpace(r.Context.IP)
	r.Context.UserAgent = strings.TrimSpace(r.Context.UserAgent)
	r.Context.Method = strings.TrimSpace(r.Context.Method)
	r.Context.Path = strings.TrimSpace(r.Context.Path)
}

func (r DecisionRequest) HasRelationshipContext() bool {
	if r.Relationships.Blocked || r.Relationships.Following || r.Relationships.Friend ||
		r.Relationships.Shared || r.Relationships.Participant || r.Relationships.Invited ||
		r.Relationships.Collaborator {
		return true
	}
	return strings.TrimSpace(r.Resource.Visibility) != "" || strings.TrimSpace(r.Resource.OwnerActorID) != ""
}
