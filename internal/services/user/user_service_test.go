package serviceuser

import (
	"context"
	"errors"
	domainauth "starter-kit/internal/domain/auth"
	domainpermission "starter-kit/internal/domain/permission"
	domainrole "starter-kit/internal/domain/role"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
	"starter-kit/utils"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type userRepoMock struct {
	user      domainuser.Users
	usersByID map[string]domainuser.Users
	updated   domainuser.Users
	emailUser domainuser.Users
	emailErr  error
	phoneUser domainuser.Users
	phoneErr  error
}

func (m *userRepoMock) Store(data domainuser.Users) error { m.user = data; return nil }
func (m *userRepoMock) GetByID(id string) (domainuser.Users, error) {
	if m.usersByID != nil {
		user, ok := m.usersByID[id]
		if !ok {
			return domainuser.Users{}, errors.New("not found")
		}
		return user, nil
	}
	return m.user, nil
}
func (m *userRepoMock) GetAll(params filter.BaseParams) ([]domainuser.Users, int64, error) {
	return nil, 0, nil
}
func (m *userRepoMock) Update(data domainuser.Users) error {
	m.updated = data
	m.user = data
	return nil
}
func (m *userRepoMock) Delete(id string) error { return nil }
func (m *userRepoMock) GetByEmail(email string) (domainuser.Users, error) {
	if m.emailErr != nil {
		return domainuser.Users{}, m.emailErr
	}
	return m.emailUser, nil
}
func (m *userRepoMock) GetByPhone(phone string) (domainuser.Users, error) {
	if m.phoneErr != nil {
		return domainuser.Users{}, m.phoneErr
	}
	return m.phoneUser, nil
}

type authRepoMock struct{}

func (m *authRepoMock) Store(data domainauth.Blacklist) error { return nil }
func (m *authRepoMock) GetByToken(token string) (domainauth.Blacklist, error) {
	return domainauth.Blacklist{}, nil
}

type roleRepoUserMock struct {
	roles map[string]domainrole.Role
}

func (m *roleRepoUserMock) Store(data domainrole.Role) error { return nil }
func (m *roleRepoUserMock) GetByID(id string) (domainrole.Role, error) {
	return domainrole.Role{}, errors.New("not implemented")
}
func (m *roleRepoUserMock) GetAll(params filter.BaseParams) ([]domainrole.Role, int64, error) {
	return nil, 0, nil
}
func (m *roleRepoUserMock) Update(data domainrole.Role) error { return nil }
func (m *roleRepoUserMock) Delete(id string) error            { return nil }
func (m *roleRepoUserMock) GetByName(name string) (domainrole.Role, error) {
	role, ok := m.roles[name]
	if !ok {
		return domainrole.Role{}, errors.New("not found")
	}
	return role, nil
}
func (m *roleRepoUserMock) AssignPermissions(roleId string, permissionIds []string) error { return nil }
func (m *roleRepoUserMock) RemovePermissions(roleId string, permissionIds []string) error { return nil }
func (m *roleRepoUserMock) GetRolePermissions(roleId string) ([]string, error)            { return nil, nil }
func (m *roleRepoUserMock) AssignMenus(roleId string, menuIds []string) error             { return nil }
func (m *roleRepoUserMock) RemoveMenus(roleId string, menuIds []string) error             { return nil }
func (m *roleRepoUserMock) GetRoleMenus(roleId string) ([]string, error)                  { return nil, nil }

type permissionRepoUserMock struct {
	userPermissions []domainpermission.Permission
}

func (m *permissionRepoUserMock) Store(data domainpermission.Permission) error { return nil }
func (m *permissionRepoUserMock) GetByID(id string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoUserMock) GetAll(params filter.BaseParams) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoUserMock) Update(data domainpermission.Permission) error { return nil }
func (m *permissionRepoUserMock) Delete(id string) error                        { return nil }
func (m *permissionRepoUserMock) GetByName(name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoUserMock) GetByResource(resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoUserMock) GetUserPermissions(userId string) ([]domainpermission.Permission, error) {
	return append([]domainpermission.Permission{}, m.userPermissions...), nil
}

func TestAdminCreateUserRequiresAssignRolePermissionForNonViewer(t *testing.T) {
	service := &ServiceUser{
		UserRepo:      &userRepoMock{},
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleStaff: {Id: "role-staff", Name: utils.RoleStaff},
		}},
		PermissionRepo: &permissionRepoUserMock{},
	}

	_, err := service.AdminCreateUser(dto.AdminCreateUser{
		Name:     "Jane Doe",
		Email:    "jane@example.com",
		Phone:    "08123456789",
		Password: "Password1!",
		Role:     utils.RoleStaff,
	}, "creator-1", utils.RoleAdmin)
	if err == nil || err.Error() != "access denied: missing permission users:assign_role" {
		t.Fatalf("expected assign_role access error, got %v", err)
	}
}

func TestUpdateRequiresAssignRolePermissionWhenChangingRole(t *testing.T) {
	service := &ServiceUser{
		UserRepo: &userRepoMock{
			user: domainuser.Users{Id: "user-1", Role: utils.RoleViewer},
		},
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleStaff: {Id: "role-staff", Name: utils.RoleStaff},
		}},
		PermissionRepo: &permissionRepoUserMock{},
	}

	_, err := service.Update("user-1", "editor-1", utils.RoleAdmin, dto.UserUpdate{Role: utils.RoleStaff})
	if err == nil || err.Error() != "access denied: missing permission users:assign_role" {
		t.Fatalf("expected assign_role access error, got %v", err)
	}
}

func TestUpdateRejectsSuperadminAssignmentForNonSuperadmin(t *testing.T) {
	service := &ServiceUser{
		UserRepo: &userRepoMock{
			user: domainuser.Users{Id: "user-1", Role: utils.RoleViewer},
		},
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleSuperAdmin: {Id: "role-superadmin", Name: utils.RoleSuperAdmin},
		}},
		PermissionRepo: &permissionRepoUserMock{
			userPermissions: []domainpermission.Permission{{Resource: "users", Action: "assign_role"}},
		},
	}

	_, err := service.Update("user-1", "editor-1", utils.RoleAdmin, dto.UserUpdate{Role: utils.RoleSuperAdmin})
	if err == nil || err.Error() != "cannot assign superadmin role" {
		t.Fatalf("expected superadmin assignment error, got %v", err)
	}
}

func TestRegisterUserNormalizesEmailToLowercase(t *testing.T) {
	service := &ServiceUser{
		UserRepo:      &userRepoMock{},
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleViewer: {Id: "role-viewer", Name: utils.RoleViewer},
		}},
		PermissionRepo: &permissionRepoUserMock{},
	}

	user, err := service.RegisterUser(dto.UserRegister{
		Name:     "Jane Doe",
		Email:    "Jane.Doe@Example.COM",
		Phone:    "08123456789",
		Password: "Password1!",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if user.Email != "jane.doe@example.com" {
		t.Fatalf("expected normalized lowercase email, got %s", user.Email)
	}
}

func TestAdminCreateUserNormalizesEmailToLowercase(t *testing.T) {
	service := &ServiceUser{
		UserRepo:      &userRepoMock{},
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleStaff: {Id: "role-staff", Name: utils.RoleStaff},
		}},
		PermissionRepo: &permissionRepoUserMock{
			userPermissions: []domainpermission.Permission{{Resource: "users", Action: "assign_role"}},
		},
	}

	user, err := service.AdminCreateUser(dto.AdminCreateUser{
		Name:     "Jane Doe",
		Email:    "Jane.Doe@Example.COM",
		Phone:    "08123456789",
		Password: "Password1!",
		Role:     utils.RoleStaff,
	}, "creator-1", utils.RoleAdmin)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if user.Email != "jane.doe@example.com" {
		t.Fatalf("expected normalized lowercase email, got %s", user.Email)
	}
}

func TestUpdateNormalizesEmailToLowercase(t *testing.T) {
	service := &ServiceUser{
		UserRepo: &userRepoMock{
			user: domainuser.Users{Id: "user-1", Role: utils.RoleViewer, Email: "old@example.com"},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	user, err := service.Update("user-1", "user-1", utils.RoleViewer, dto.UserUpdate{
		Email: "Jane.Doe@Example.COM",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if user.Email != "jane.doe@example.com" {
		t.Fatalf("expected normalized lowercase email, got %s", user.Email)
	}
}

func TestLoginUserAcceptsEmailIdentifier(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	service := &ServiceUser{
		UserRepo: &userRepoMock{
			emailUser: domainuser.Users{
				Id:       "user-1",
				Name:     "Jane Doe",
				Email:    "jane.doe@example.com",
				Password: string(hashedPassword),
				Role:     utils.RoleViewer,
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	token, err := service.LoginUser(dto.Login{
		Identifier: "Jane.Doe@Example.COM",
		Password:   "Password1!",
	}, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestLoginUserAcceptsPhoneIdentifier(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	service := &ServiceUser{
		UserRepo: &userRepoMock{
			phoneUser: domainuser.Users{
				Id:       "user-1",
				Name:     "Jane Doe",
				Phone:    "628123456789",
				Password: string(hashedPassword),
				Role:     utils.RoleViewer,
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	token, err := service.LoginUser(dto.Login{
		Identifier: "08123456789",
		Password:   "Password1!",
	}, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestLoginUserRejectsInvalidRandomIdentifier(t *testing.T) {
	service := &ServiceUser{
		UserRepo:       &userRepoMock{},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	_, err := service.LoginUser(dto.Login{
		Identifier: "randomtext",
		Password:   "Password1!",
	}, "log-1")
	if err == nil || err.Error() != "identifier must be a valid email or phone number" {
		t.Fatalf("expected invalid identifier error, got %v", err)
	}
}

func TestImpersonateUserGeneratesTokenWithOriginalUserClaims(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	service := &ServiceUser{
		UserRepo: &userRepoMock{
			usersByID: map[string]domainuser.Users{
				"target-1": {
					Id:    "target-1",
					Name:  "Target User",
					Role:  utils.RoleStaff,
					Email: "target@example.com",
				},
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	token, err := service.ImpersonateUser("target-1", "admin-1", "Admin User", utils.RoleAdmin, false, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := utils.JwtClaim(token)
	if err != nil {
		t.Fatalf("failed to parse token claims: %v", err)
	}

	if claims["user_id"] != "target-1" {
		t.Fatalf("expected target user id in claims, got %v", claims["user_id"])
	}
	if claims["is_impersonated"] != true {
		t.Fatalf("expected impersonation flag in claims, got %v", claims["is_impersonated"])
	}
	if claims["original_user_id"] != "admin-1" {
		t.Fatalf("expected original user id in claims, got %v", claims["original_user_id"])
	}
}

func TestImpersonateUserRejectsSuperadminTargetForNonSuperadmin(t *testing.T) {
	service := &ServiceUser{
		UserRepo: &userRepoMock{
			usersByID: map[string]domainuser.Users{
				"target-1": {
					Id:   "target-1",
					Name: "Superadmin User",
					Role: utils.RoleSuperAdmin,
				},
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	_, err := service.ImpersonateUser("target-1", "admin-1", "Admin User", utils.RoleAdmin, false, "log-1")
	if err == nil || err.Error() != "cannot impersonate superadmin users" {
		t.Fatalf("expected superadmin impersonation error, got %v", err)
	}
}

func TestStopImpersonationReturnsOriginalUserToken(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	service := &ServiceUser{
		UserRepo: &userRepoMock{
			usersByID: map[string]domainuser.Users{
				"admin-1": {
					Id:   "admin-1",
					Name: "Admin User",
					Role: utils.RoleAdmin,
				},
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	token, err := service.StopImpersonation("admin-1", "target-1", "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := utils.JwtClaim(token)
	if err != nil {
		t.Fatalf("failed to parse token claims: %v", err)
	}

	if claims["user_id"] != "admin-1" {
		t.Fatalf("expected original user id in claims, got %v", claims["user_id"])
	}
	if _, exists := claims["is_impersonated"]; exists {
		t.Fatalf("expected impersonation flag to be absent after stop, got %v", claims["is_impersonated"])
	}
}

func TestLoginWithGoogleReturnsExistingUser(t *testing.T) {
	originalVerifier := googleIDTokenVerifier
	googleIDTokenVerifier = func(_ context.Context, idToken string) (googleTokenInfo, error) {
		return googleTokenInfo{
			Email:         "Jane.Doe@Example.COM",
			EmailVerified: "true",
			Subject:       "google-sub-1",
			Name:          "Jane Doe",
			Audience:      "client-id",
		}, nil
	}
	defer func() { googleIDTokenVerifier = originalVerifier }()

	service := &ServiceUser{
		UserRepo: &userRepoMock{
			emailUser: domainuser.Users{
				Id:    "user-1",
				Name:  "Jane Doe",
				Email: "jane.doe@example.com",
				Role:  utils.RoleViewer,
			},
		},
		BlacklistRepo:  &authRepoMock{},
		RoleRepo:       &roleRepoUserMock{},
		PermissionRepo: &permissionRepoUserMock{},
	}

	user, isNewUser, err := service.LoginWithGoogle(dto.GoogleLogin{IDToken: "token"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if isNewUser {
		t.Fatal("expected existing user login, got isNewUser=true")
	}
	if user.Id != "user-1" {
		t.Fatalf("expected existing user, got %+v", user)
	}
}

func TestLoginWithGoogleCreatesNewViewerUser(t *testing.T) {
	originalVerifier := googleIDTokenVerifier
	googleIDTokenVerifier = func(_ context.Context, idToken string) (googleTokenInfo, error) {
		return googleTokenInfo{
			Email:         "New.User@Example.COM",
			EmailVerified: "true",
			Subject:       "google-sub-2",
			Name:          "new user",
			Audience:      "client-id",
		}, nil
	}
	defer func() { googleIDTokenVerifier = originalVerifier }()

	userRepo := &userRepoMock{emailErr: gorm.ErrRecordNotFound}
	service := &ServiceUser{
		UserRepo:      userRepo,
		BlacklistRepo: &authRepoMock{},
		RoleRepo: &roleRepoUserMock{roles: map[string]domainrole.Role{
			utils.RoleViewer: {Id: "role-viewer", Name: utils.RoleViewer},
		}},
		PermissionRepo: &permissionRepoUserMock{},
	}

	user, isNewUser, err := service.LoginWithGoogle(dto.GoogleLogin{IDToken: "token"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !isNewUser {
		t.Fatal("expected new user registration, got isNewUser=false")
	}
	if user.Email != "new.user@example.com" {
		t.Fatalf("expected normalized email, got %s", user.Email)
	}
	if user.Role != utils.RoleViewer {
		t.Fatalf("expected viewer role, got %s", user.Role)
	}
	if userRepo.user.Password == "" {
		t.Fatal("expected generated password hash for google user")
	}
}
