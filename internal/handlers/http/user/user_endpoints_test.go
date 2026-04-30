package handleruser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"starter-kit/internal/authscope"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
)

type userServiceTestDouble struct {
	user domainuser.Users
}

func (s *userServiceTestDouble) RegisterUser(ctx context.Context, req dto.UserRegister) (domainuser.Users, error) {
	s.user.Name = req.Name
	s.user.Email = req.Email
	s.user.Phone = req.Phone
	return s.user, nil
}
func (s *userServiceTestDouble) AdminCreateUser(ctx context.Context, req dto.AdminCreateUser) (domainuser.Users, error) {
	s.user.Name = req.Name
	s.user.Email = req.Email
	s.user.Phone = req.Phone
	s.user.Role = req.Role
	return s.user, nil
}
func (s *userServiceTestDouble) LoginUser(ctx context.Context, req dto.Login, logId string, metadata dto.LoginMetadata) (string, error) {
	return "access-token", nil
}
func (s *userServiceTestDouble) LoginWithGoogle(ctx context.Context, req dto.GoogleLogin, metadata dto.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error) {
	return s.user, false, nil
}
func (s *userServiceTestDouble) LogoutUser(ctx context.Context, token string) error {
	return nil
}
func (s *userServiceTestDouble) ImpersonateUser(ctx context.Context, targetUserId string, logId string) (string, error) {
	return "impersonation-token", nil
}
func (s *userServiceTestDouble) StopImpersonation(ctx context.Context, logId string) (string, error) {
	return "restored-token", nil
}
func (s *userServiceTestDouble) GetUserById(ctx context.Context, id string) (domainuser.Users, error) {
	s.user.Id = id
	return s.user, nil
}
func (s *userServiceTestDouble) GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error) {
	if s.user.Email == email {
		return s.user, nil
	}
	return domainuser.Users{}, nil
}
func (s *userServiceTestDouble) GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error) {
	return s.user, nil
}
func (s *userServiceTestDouble) GetUserByAuth(ctx context.Context, id string) (map[string]interface{}, error) {
	return map[string]interface{}{"id": id, "name": s.user.Name, "role": s.user.Role}, nil
}
func (s *userServiceTestDouble) GetAllUsers(ctx context.Context, params filter.BaseParams) ([]domainuser.Users, int64, error) {
	return []domainuser.Users{s.user}, 1, nil
}
func (s *userServiceTestDouble) Update(ctx context.Context, id string, req dto.UserUpdate) (domainuser.Users, error) {
	s.user.Id = id
	if req.Name != "" {
		s.user.Name = req.Name
	}
	if req.Email != "" {
		s.user.Email = req.Email
	}
	if req.Phone != "" {
		s.user.Phone = req.Phone
	}
	if req.Role != "" {
		s.user.Role = req.Role
	}
	return s.user, nil
}
func (s *userServiceTestDouble) ChangePassword(ctx context.Context, id string, req dto.ChangePassword) (domainuser.Users, error) {
	s.user.Id = id
	return s.user, nil
}
func (s *userServiceTestDouble) ForgotPassword(ctx context.Context, req dto.ForgotPasswordRequest) (string, error) {
	return "reset-token", nil
}
func (s *userServiceTestDouble) ResetPassword(ctx context.Context, req dto.ResetPasswordRequest) error {
	return nil
}
func (s *userServiceTestDouble) ResetPasswordByEmail(ctx context.Context, email, newPassword string) error {
	return nil
}
func (s *userServiceTestDouble) Delete(ctx context.Context, id string) error {
	return nil
}

func newUserHandlerTestContext(t *testing.T, method, path, body string, scope *authscope.Scope) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if scope != nil {
		req = req.WithContext(authscope.WithContext(req.Context(), *scope))
	}
	ctx.Request = req
	return ctx, rec
}

func newUserHandlerForTest() *HandlerUser {
	service := &userServiceTestDouble{user: domainuser.Users{
		Id:    "user-1",
		Name:  "Jane Doe",
		Email: "jane@example.com",
		Phone: "628123456789",
		Role:  "user",
	}}
	return NewUserHandler(service, nil, nil, nil, nil, nil, nil, nil)
}

func assertUserHandlerStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected status %d, got %d body=%s", want, rec.Code, rec.Body.String())
	}
}

func TestNewUserHandlerWiresDependencies(t *testing.T) {
	service := &userServiceTestDouble{}
	handler := NewUserHandler(service, nil, nil, nil, nil, nil, nil, nil)
	if handler.Service != service {
		t.Fatal("expected service to be assigned")
	}
}

func TestUserHandlerPublicAndAdminFlows(t *testing.T) {
	handler := newUserHandlerForTest()

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusCreated)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/admin/users", `{"name":"Admin User","email":"admin@example.com","phone":"628123456780","password":"secret123","role":"admin"}`, nil)
	handler.AdminCreateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusCreated)

	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/users?page=1&limit=10&role=user", "", nil)
	handler.GetAllUsers(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerReadUpdateAndDeleteFlows(t *testing.T) {
	handler := newUserHandlerForTest()
	userID := uuid.NewString()
	scope := authscope.New(userID, "Jane Doe", "user", nil)

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/users/"+userID, "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.GetUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/me", "", &scope)
	handler.GetUserByAuth(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me", `{"name":"Jane Updated"}`, &scope)
	handler.Update(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/users/"+userID, `{"role":"admin"}`, nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.UpdateUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me/password", `{"current_password":"secret123","new_password":"secret456"}`, &scope)
	handler.ChangePassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/me", "", &scope)
	handler.Delete(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/users/"+userID, "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.DeleteUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerPasswordAndSessionFlows(t *testing.T) {
	handler := newUserHandlerForTest()
	userID := uuid.NewString()

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/logout", "", nil)
	ctx.Set("token", "access-token")
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/users/"+userID+"/impersonate", "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.ImpersonateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerUnauthorizedSelfServiceBranches(t *testing.T) {
	handler := newUserHandlerForTest()

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/me", "", nil)
	handler.GetUserByAuth(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me", `{"name":"Jane"}`, nil)
	handler.Update(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me/password", `{"current_password":"secret123","new_password":"secret456"}`, nil)
	handler.ChangePassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/me", "", nil)
	handler.Delete(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)
}
