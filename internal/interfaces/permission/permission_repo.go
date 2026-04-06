package interfacepermission

import (
	domainpermission "starter-kit/internal/domain/permission"
	interfacegeneric "starter-kit/internal/interfaces/generic"
)

type RepoPermissionInterface interface {
	interfacegeneric.GenericRepository[domainpermission.Permission]

	GetByName(name string) (domainpermission.Permission, error)
	GetByResource(resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(userId string) ([]domainpermission.Permission, error)
}
