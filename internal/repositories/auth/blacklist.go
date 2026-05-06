package repositoryauth

import (
	"context"
	domainauth "starter-kit/internal/domain/auth"
	interfaceauth "starter-kit/internal/interfaces/auth"
	repositorygeneric "starter-kit/internal/repositories/generic"

	"gorm.io/gorm"
)

type blacklistRepo struct {
	*repositorygeneric.GenericRepository[domainauth.Blacklist]
}

func NewBlacklistRepo(db *gorm.DB) interfaceauth.RepoAuthInterface {
	return &blacklistRepo{
		GenericRepository: repositorygeneric.New[domainauth.Blacklist](db),
	}
}

func (r *blacklistRepo) GetByToken(ctx context.Context, token string) (domainauth.Blacklist, error) {
	return r.GetOneByField(ctx, "token", token)
}

func (r *blacklistRepo) ExistsByToken(ctx context.Context, token string) (bool, error) {
	return r.ExistsByField(ctx, "token", token)
}
