package interfacepermission

import (
	domainpermission "starter-kit/internal/domain/permission"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoPermissionInterface interface {
	interfacebase.GenericRepository[domainpermission.Permission]

	GetByName(name string) (domainpermission.Permission, error)
	GetByResource(resource string) ([]domainpermission.Permission, error)
	GetUserPermissions(userId string) ([]domainpermission.Permission, error)
}
