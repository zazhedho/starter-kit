package interfaceuser

import (
	domainuser "starter-kit/internal/domain/user"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoUserInterface interface {
	interfacebase.GenericRepository[domainuser.Users]

	GetByEmail(email string) (domainuser.Users, error)
	GetByPhone(phone string) (domainuser.Users, error)
}
