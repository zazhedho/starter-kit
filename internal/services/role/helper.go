package servicerole

import domainpermission "starter-kit/internal/domain/permission"

func hasPermission(permissions []domainpermission.Permission, resource, action string) bool {
	for _, permission := range permissions {
		if permission.Resource == resource && permission.Action == action {
			return true
		}
	}

	return false
}
