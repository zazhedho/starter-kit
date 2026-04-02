package interfacerole

import (
	domainrole "starter-kit/internal/domain/role"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoRoleInterface interface {
	interfacebase.GenericRepository[domainrole.Role]

	GetByName(name string) (domainrole.Role, error)

	AssignPermissions(roleId string, permissionIds []string) error
	RemovePermissions(roleId string, permissionIds []string) error
	GetRolePermissions(roleId string) ([]string, error)

	AssignMenus(roleId string, menuIds []string) error
	RemoveMenus(roleId string, menuIds []string) error
	GetRoleMenus(roleId string) ([]string, error)
}
