package interfaceuser

import (
	domainuser "team-leader-development-program/internal/domain/user"
	"team-leader-development-program/internal/dto"
	"team-leader-development-program/pkg/filter"
)

type ServiceUserInterface interface {
	RegisterUser(req dto.UserRegister) (domainuser.Users, error)
	LoginUser(req dto.Login, logId string) (string, error)
	LogoutUser(token string) error
	GetUserById(id string) (domainuser.Users, error)
	GetUserByEmail(email string) (domainuser.Users, error)
	GetUserByAuth(id string) (map[string]interface{}, error)
	GetAllUsers(params filter.BaseParams, currentUserRole string) ([]domainuser.Users, int64, error)
	Update(id, role string, req dto.UserUpdate) (domainuser.Users, error)
	ChangePassword(id string, req dto.ChangePassword) (domainuser.Users, error)
	ForgotPassword(req dto.ForgotPasswordRequest) (string, error)
	ResetPassword(req dto.ResetPasswordRequest) error
	Delete(id string) error
}
