package interfacerole

import (
	domainrole "starter-kit/internal/domain/role"
	interfacegeneric "starter-kit/internal/interfaces/generic"
)

type RepoRoleInterface interface {
	interfacegeneric.GenericRepository[domainrole.Role]

	GetByName(name string) (domainrole.Role, error)

	AssignPermissions(roleId string, permissionIds []string) error
	RemovePermissions(roleId string, permissionIds []string) error
	GetRolePermissions(roleId string) ([]string, error)

	AssignMenus(roleId string, menuIds []string) error
	RemoveMenus(roleId string, menuIds []string) error
	GetRoleMenus(roleId string) ([]string, error)
}
