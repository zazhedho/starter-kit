package repositorymedia

import (
	"context"
	"errors"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
	interfacemedia "starter-kit/internal/interfaces/media"
)

type repo struct {
	*gokit.Repository[domainmedia.Media]
}

func NewMediaRepo(db *gorm.DB) interfacemedia.RepoMediaInterface {
	return &repo{Repository: gokit.NewRepository[domainmedia.Media](db)}
}

// GetByID shadows the embedded generic lookup to translate the ORM's
// missing-row error into domainmedia.ErrNotFound.
func (r *repo) GetByID(ctx context.Context, id string) (domainmedia.Media, error) {
	media, err := r.Repository.GetByID(ctx, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domainmedia.Media{}, domainmedia.ErrNotFound
	}
	return media, err
}

var _ interfacemedia.RepoMediaInterface = (*repo)(nil)
