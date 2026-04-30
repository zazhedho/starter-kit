package middlewares

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	domainauth "starter-kit/internal/domain/auth"
	domainpermission "starter-kit/internal/domain/permission"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/pkg/filter"
	"starter-kit/utils"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type authRepoTestDouble struct {
	blacklisted bool
	err         error
	stored      domainauth.Blacklist
}

func (m *authRepoTestDouble) Store(data domainauth.Blacklist) error {
	m.stored = data
	return nil
}

func (m *authRepoTestDouble) GetByToken(token string) (domainauth.Blacklist, error) {
	return domainauth.Blacklist{Token: token}, nil
}

func (m *authRepoTestDouble) ExistsByToken(token string) (bool, error) {
	return m.blacklisted, m.err
}

type permissionRepoTestDouble struct {
	permissions []domainpermission.Permission
	err         error
}

func (m *permissionRepoTestDouble) Store(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoTestDouble) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoTestDouble) GetAll(ctx context.Context, params filter.BaseParams) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoTestDouble) Update(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoTestDouble) Delete(ctx context.Context, id string) error { return nil }
func (m *permissionRepoTestDouble) GetByName(ctx context.Context, name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoTestDouble) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoTestDouble) GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error) {
	if m.err != nil {
		return nil, m.err
	}
	return append([]domainpermission.Permission{}, m.permissions...), nil
}

func performMiddlewareRequest(token string, handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", append(handlers, func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})...)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	router.ServeHTTP(rec, req)
	return rec
}

func performMiddlewareRequestWithSetup(handlers []gin.HandlerFunc, setup func(*gin.Context)) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	chain := []gin.HandlerFunc{func(ctx *gin.Context) {
		if setup != nil {
			setup(ctx)
		}
		ctx.Next()
	}}
	chain = append(chain, handlers...)
	chain = append(chain, func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})
	router.GET("/protected", chain...)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	router.ServeHTTP(rec, req)
	return rec
}

func testToken(t *testing.T, tokenType string, role string) string {
	t.Helper()
	t.Setenv("JWT_KEY", "test-secret-must-be-at-least-32-bytes")

	claims := &utils.AppClaims{TokenType: tokenType}
	token, err := utils.GenerateJwtWithClaims(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: role,
	}, "log-1", claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func TestAuthMiddlewareAllowsValidAccessToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{})
	rec := performMiddlewareRequest(testToken(t, "access", utils.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsRefreshToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{})
	rec := performMiddlewareRequest(testToken(t, "refresh", utils.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsBlacklistedToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{blacklisted: true}, &permissionRepoTestDouble{})
	rec := performMiddlewareRequest(testToken(t, "access", utils.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsInvalidTokenAndBlacklistError(t *testing.T) {
	tests := []struct {
		name string
		repo *authRepoTestDouble
		code int
	}{
		{
			name: "invalid token",
			repo: &authRepoTestDouble{},
			code: http.StatusUnauthorized,
		},
		{
			name: "blacklist error",
			repo: &authRepoTestDouble{err: errors.New("redis down")},
			code: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := "not-a-token"
			if tt.name == "blacklist error" {
				token = testToken(t, "access", utils.RoleViewer)
			}
			mdw := NewMiddleware(tt.repo, &permissionRepoTestDouble{})
			rec := performMiddlewareRequest(token, mdw.AuthMiddleware())
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRoleMiddlewareBranches(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*gin.Context)
		allowed []string
		code    int
	}{
		{
			name: "missing auth data",
			code: http.StatusForbidden,
		},
		{
			name: "invalid auth data",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "empty role",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, map[string]interface{}{"role": " "})
			},
			code: http.StatusForbidden,
		},
		{
			name: "disallowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, map[string]interface{}{"role": utils.RoleViewer})
			},
			allowed: []string{utils.RoleAdmin},
			code:    http.StatusForbidden,
		},
		{
			name: "allowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, map[string]interface{}{"role": utils.RoleAdmin})
			},
			allowed: []string{utils.RoleAdmin},
			code:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{})
			rec := performMiddlewareRequestWithSetup([]gin.HandlerFunc{mdw.RoleMiddleware(tt.allowed...)}, tt.setup)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPermissionMiddlewareAllowsOwnedPermission(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "list"}},
	})

	rec := performMiddlewareRequest(
		testToken(t, "access", utils.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "list"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareRejectsMissingPermission(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "view"}},
	})

	rec := performMiddlewareRequest(
		testToken(t, "access", utils.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "delete"),
	)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareBypassesSuperadmin(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{})
	rec := performMiddlewareRequest(
		testToken(t, "access", utils.RoleSuperAdmin),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("anything", "delete"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareRejectsInvalidAuthData(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*gin.Context)
		code  int
	}{
		{
			name: "missing auth data",
			code: http.StatusForbidden,
		},
		{
			name: "invalid auth data type",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing role",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, map[string]interface{}{"user_id": "user-1"})
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing user id",
			setup: func(ctx *gin.Context) {
				ctx.Set(utils.CtxKeyAuthData, map[string]interface{}{"role": utils.RoleViewer})
			},
			code: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{})
			rec := performMiddlewareRequestWithSetup([]gin.HandlerFunc{mdw.PermissionMiddleware("users", "read")}, tt.setup)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPermissionMiddlewareHandlesRepositoryErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "record not found", err: gorm.ErrRecordNotFound, code: http.StatusForbidden},
		{name: "unexpected error", err: errors.New("db down"), code: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{err: tt.err})
			rec := performMiddlewareRequest(
				testToken(t, "access", utils.RoleViewer),
				mdw.AuthMiddleware(),
				mdw.PermissionMiddleware("users", "read"),
			)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}
