package authz

import "strings"

func evaluateRBAC(perms []string, action string) (bool, string) {
	for _, perm := range perms {
		if permissionMatches(action, perm) {
			return true, "rbac:" + perm
		}
	}
	return false, ""
}

func permissionMatches(action, perm string) bool {
	action = strings.TrimSpace(strings.ToLower(action))
	perm = strings.TrimSpace(strings.ToLower(perm))

	if perm == "*" {
		return true
	}
	if strings.HasSuffix(perm, "*") {
		prefix := strings.TrimSuffix(perm, "*")
		return strings.HasPrefix(action, prefix)
	}
	return action == perm
}
