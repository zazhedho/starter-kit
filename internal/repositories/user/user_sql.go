package repositoryuser

import (
	domainuser "starter-kit/internal/domain/user"
	interfaceuser "starter-kit/internal/interfaces/user"
	repositorygeneric "starter-kit/internal/repositories/generic"
	"starter-kit/pkg/filter"

	"gorm.io/gorm"
)

type repo struct {
	*repositorygeneric.GenericRepository[domainuser.Users]
}

func NewUserRepo(db *gorm.DB) interfaceuser.RepoUserInterface {
	return &repo{GenericRepository: repositorygeneric.New[domainuser.Users](db)}
}

func (r *repo) GetByEmail(email string) (ret domainuser.Users, err error) {
	return r.GetOneByField("email", email)
}

func (r *repo) GetByPhone(phone string) (ret domainuser.Users, err error) {
	return r.GetOneByField("phone", phone)
}

func (r *repo) GetAll(params filter.BaseParams) (ret []domainuser.Users, totalData int64, err error) {
	return r.GenericRepository.GetAll(params, repositorygeneric.QueryOptions{
		Search:         repositorygeneric.BuildSearchFunc("name", "email", "phone"),
		AllowedFilters: []string{"id", "name", "email", "phone", "role", "role_id", "created_at", "updated_at"},
		AllowedOrderColumns: []string{
			"name",
			"email",
			"phone",
			"role",
			"last_login_at",
			"login_provider",
			"created_at",
			"updated_at",
		},
	})
}
