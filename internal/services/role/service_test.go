package servicerole

import (
	"errors"
	domainmenu "starter-kit/internal/domain/menu"
	domainpermission "starter-kit/internal/domain/permission"
	domainrole "starter-kit/internal/domain/role"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
	"starter-kit/utils"
	"testing"
)

type roleRepoMock struct {
	role                domainrole.Role
	rolePermissions     []string
	assignedPermissions []string
}

func (m *roleRepoMock) Store(data domainrole.Role) error           { return nil }
func (m *roleRepoMock) GetByID(id string) (domainrole.Role, error) { return m.role, nil }
func (m *roleRepoMock) GetAll(params filter.BaseParams) ([]domainrole.Role, int64, error) {
	return nil, 0, nil
}
func (m *roleRepoMock) Update(data domainrole.Role) error { return nil }
func (m *roleRepoMock) Delete(id string) error            { return nil }
func (m *roleRepoMock) GetByName(name string) (domainrole.Role, error) {
	return domainrole.Role{}, errors.New("not implemented")
}
func (m *roleRepoMock) AssignPermissions(roleId string, permissionIds []string) error {
	m.assignedPermissions = append([]string{}, permissionIds...)
	return nil
}
func (m *roleRepoMock) RemovePermissions(roleId string, permissionIds []string) error { return nil }
func (m *roleRepoMock) GetRolePermissions(roleId string) ([]string, error) {
	return m.rolePermissions, nil
}
func (m *roleRepoMock) AssignMenus(roleId string, menuIds []string) error { return nil }
func (m *roleRepoMock) RemoveMenus(roleId string, menuIds []string) error { return nil }
func (m *roleRepoMock) GetRoleMenus(roleId string) ([]string, error)      { return nil, nil }

type permissionRepoMock struct {
	permissionsByID map[string]domainpermission.Permission
	userPermissions []domainpermission.Permission
}

func (m *permissionRepoMock) Store(data domainpermission.Permission) error { return nil }
func (m *permissionRepoMock) GetByID(id string) (domainpermission.Permission, error) {
	permission, ok := m.permissionsByID[id]
	if !ok {
		return domainpermission.Permission{}, errors.New("not found")
	}
	return permission, nil
}
func (m *permissionRepoMock) GetAll(params filter.BaseParams) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoMock) Update(data domainpermission.Permission) error { return nil }
func (m *permissionRepoMock) Delete(id string) error                        { return nil }
func (m *permissionRepoMock) GetByName(name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoMock) GetByResource(resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoMock) GetUserPermissions(userId string) ([]domainpermission.Permission, error) {
	return append([]domainpermission.Permission{}, m.userPermissions...), nil
}

type menuRepoMock struct {
	activeMenus []domainmenu.MenuItem
}

func (m *menuRepoMock) Store(data domainmenu.MenuItem) error { return nil }
func (m *menuRepoMock) GetByID(id string) (domainmenu.MenuItem, error) {
	return domainmenu.MenuItem{}, errors.New("not implemented")
}
func (m *menuRepoMock) GetAll(params filter.BaseParams) ([]domainmenu.MenuItem, int64, error) {
	return nil, 0, nil
}
func (m *menuRepoMock) Update(data domainmenu.MenuItem) error { return nil }
func (m *menuRepoMock) Delete(id string) error                { return nil }
func (m *menuRepoMock) GetByName(name string) (domainmenu.MenuItem, error) {
	return domainmenu.MenuItem{}, errors.New("not implemented")
}
func (m *menuRepoMock) GetActiveMenus() ([]domainmenu.MenuItem, error) {
	return append([]domainmenu.MenuItem{}, m.activeMenus...), nil
}
func (m *menuRepoMock) GetUserMenus(userId string) ([]domainmenu.MenuItem, error) { return nil, nil }

func TestAssignPermissionsRequiresManageSystemPermissionForSystemRole(t *testing.T) {
	service := &RoleService{
		RoleRepo: &roleRepoMock{
			role: domainrole.Role{Id: "role-1", Name: utils.RoleAdmin, IsSystem: true},
		},
		PermissionRepo: &permissionRepoMock{},
		MenuRepo:       &menuRepoMock{},
	}

	err := service.AssignPermissions("role-1", dto.AssignPermissions{PermissionIds: []string{"perm-1"}}, "user-1", utils.RoleStaff)
	if err == nil || err.Error() != "access denied: missing permission roles:manage_system" {
		t.Fatalf("expected manage_system access error, got %v", err)
	}
}

func TestAssignPermissionsRejectsSuperadminRoleForNonSuperadmin(t *testing.T) {
	service := &RoleService{
		RoleRepo: &roleRepoMock{
			role: domainrole.Role{Id: "role-1", Name: utils.RoleSuperAdmin, IsSystem: true},
		},
		PermissionRepo: &permissionRepoMock{
			userPermissions: []domainpermission.Permission{{Resource: "roles", Action: "manage_system"}},
		},
		MenuRepo: &menuRepoMock{},
	}

	err := service.AssignPermissions("role-1", dto.AssignPermissions{PermissionIds: []string{"perm-1"}}, "user-1", utils.RoleAdmin)
	if err == nil || err.Error() != "access denied: cannot modify superadmin role" {
		t.Fatalf("expected superadmin protection error, got %v", err)
	}
}

func TestAssignPermissionsAllowsSystemRoleWhenPermissionPresent(t *testing.T) {
	roleRepo := &roleRepoMock{
		role: domainrole.Role{Id: "role-1", Name: utils.RoleAdmin, IsSystem: true},
	}
	service := &RoleService{
		RoleRepo: roleRepo,
		PermissionRepo: &permissionRepoMock{
			userPermissions: []domainpermission.Permission{{Resource: "roles", Action: "manage_system"}},
			permissionsByID: map[string]domainpermission.Permission{
				"perm-1": {Id: "perm-1", Resource: "users", Action: "view"},
			},
		},
		MenuRepo: &menuRepoMock{},
	}

	err := service.AssignPermissions("role-1", dto.AssignPermissions{PermissionIds: []string{"perm-1"}}, "user-1", utils.RoleAdmin)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if len(roleRepo.assignedPermissions) != 1 || roleRepo.assignedPermissions[0] != "perm-1" {
		t.Fatalf("expected assigned permission to be stored, got %v", roleRepo.assignedPermissions)
	}
}
