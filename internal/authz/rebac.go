package authz

import "strings"

func evaluateRelationshipDeny(req DecisionRequest) (string, bool) {
	if !req.HasRelationshipContext() {
		return "", false
	}
	if req.Relationships.Blocked {
		return "blocked", true
	}
	return "", false
}

func evaluateRelationship(req DecisionRequest) (DecisionResponse, bool) {
	if !req.HasRelationshipContext() {
		return DecisionResponse{}, false
	}
	if !isReadLikeAction(req.Action) {
		return DecisionResponse{}, false
	}

	switch req.Resource.Visibility {
	case "":
		return DecisionResponse{}, false
	case "public":
		return DecisionResponse{Allow: true, Reason: "visibility_public"}, true
	case "friends_only":
		if req.Relationships.Friend {
			return DecisionResponse{Allow: true, Reason: "visibility_friends"}, true
		}
	case "followers_only":
		if req.Relationships.Following {
			return DecisionResponse{Allow: true, Reason: "visibility_followers"}, true
		}
	case "shared":
		if req.Relationships.Shared || req.Relationships.Collaborator {
			return DecisionResponse{Allow: true, Reason: "visibility_shared"}, true
		}
	case "invite_only":
		if req.Relationships.Invited || req.Relationships.Participant {
			return DecisionResponse{Allow: true, Reason: "visibility_invited"}, true
		}
	case "participants_only":
		if req.Relationships.Participant {
			return DecisionResponse{Allow: true, Reason: "visibility_participant"}, true
		}
	case "private":
		// owner/actor ownership is handled separately.
	default:
		return DecisionResponse{}, false
	}

	return DecisionResponse{Allow: false, Reason: "visibility_denied"}, true
}

func isReadLikeAction(action string) bool {
	action = strings.TrimSpace(strings.ToLower(action))
	if action == "" {
		return false
	}
	if strings.HasSuffix(action, ":read") || strings.HasSuffix(action, ":view") || strings.HasSuffix(action, ":list") || strings.HasSuffix(action, ":search") {
		return true
	}
	switch action {
	case "read", "view", "list", "search":
		return true
	}
	return false
}
