package repositorymedia

import (
	"context"
	"errors"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
)

// Repository is the GORM adapter for the media table. It embeds the generic
// gokit repository and overrides GetByID to translate the ORM not-found error.
type Repository struct {
	*gokit.Repository[domainmedia.Media]
}

// NewRepository returns a Repository over db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainmedia.Media](db)}
}

// GetByID shadows the embedded generic lookup to translate the ORM's
// missing-row error into domainmedia.ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, id string) (domainmedia.Media, error) {
	media, err := r.Repository.GetByID(ctx, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domainmedia.Media{}, domainmedia.ErrNotFound
	}
	return media, err
}
