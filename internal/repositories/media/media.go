package repositorymedia

import (
	"github.com/zazhedho/gokit"
	domainmedia "starter-kit/internal/domain/media"
	interfacemedia "starter-kit/internal/interfaces/media"

	"gorm.io/gorm"
)

type repo struct {
	*gokit.Repository[domainmedia.Media]
}

func NewMediaRepo(db *gorm.DB) interfacemedia.RepoMediaInterface {
	return &repo{Repository: gokit.NewRepository[domainmedia.Media](db)}
}

var _ interfacemedia.RepoMediaInterface = (*repo)(nil)
