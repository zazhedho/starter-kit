package interfaceuser

import (
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
)

type ServiceUserInterface interface {
	RegisterUser(req dto.UserRegister) (domainuser.Users, error)
	AdminCreateUser(req dto.AdminCreateUser, creatorUserId string, creatorRole string) (domainuser.Users, error)
	LoginUser(req dto.Login, logId string, metadata dto.LoginMetadata) (string, error)
	LoginWithGoogle(req dto.GoogleLogin, metadata dto.LoginMetadata) (domainuser.Users, bool, error)
	LogoutUser(token string) error
	ImpersonateUser(targetUserId, impersonatorUserId, impersonatorName, impersonatorRole string, alreadyImpersonated bool, logId string) (string, error)
	StopImpersonation(originalUserId, currentUserId string, logId string) (string, error)
	GetUserById(id string) (domainuser.Users, error)
	GetUserByEmail(email string) (domainuser.Users, error)
	GetUserByPhone(phone string) (domainuser.Users, error)
	GetUserByAuth(id string) (map[string]interface{}, error)
	GetAllUsers(params filter.BaseParams, currentUserRole string) ([]domainuser.Users, int64, error)
	Update(id, currentUserId, currentUserRole string, req dto.UserUpdate) (domainuser.Users, error)
	ChangePassword(id string, req dto.ChangePassword) (domainuser.Users, error)
	ForgotPassword(req dto.ForgotPasswordRequest) (string, error)
	ResetPassword(req dto.ResetPasswordRequest) error
	ResetPasswordByEmail(email, newPassword string) error
	Delete(id string) error
}
