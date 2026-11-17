package repositorymedia

import (
	repositorygeneric "github.com/zazhedho/gokit/repository/generic"
	domainmedia "starter-kit/internal/domain/media"
	interfacemedia "starter-kit/internal/interfaces/media"

	"gorm.io/gorm"
)

type repo struct {
	*repositorygeneric.GenericRepository[domainmedia.Media]
}

func NewMediaRepo(db *gorm.DB) interfacemedia.RepoMediaInterface {
	return &repo{GenericRepository: repositorygeneric.New[domainmedia.Media](db)}
}

var _ interfacemedia.RepoMediaInterface = (*repo)(nil)
