package interfaceuser

import (
	domainuser "starter-kit/internal/domain/user"
	interfacegeneric "starter-kit/internal/interfaces/generic"
)

type RepoUserInterface interface {
	interfacegeneric.GenericRepository[domainuser.Users]

	GetByEmail(email string) (domainuser.Users, error)
	GetByPhone(phone string) (domainuser.Users, error)
}
