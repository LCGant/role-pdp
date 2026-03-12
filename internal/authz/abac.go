package authz

import "strings"

func evaluateOwnership(req DecisionRequest) (bool, string) {
	if req.Resource.OwnerID == "" || req.Subject.UserID == "" {
		return false, ""
	}
	if req.Resource.TenantID != "" && req.Resource.TenantID != req.Subject.TenantID {
		return false, ""
	}

	actionParts := strings.Split(req.Action, ":")
	if len(actionParts) != 2 {
		return false, ""
	}
	resourcePrefix, verb := actionParts[0], actionParts[1]
	if resourcePrefix != req.Resource.Type {
		return false, ""
	}

	switch verb {
	case "read", "update":
		if req.Resource.OwnerID == req.Subject.UserID {
			return true, "owner_" + verb
		}
	}
	return false, ""
}
