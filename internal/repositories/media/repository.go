package media

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

var (
	listOrderColumns = []string{"created_at", "size", "original_name"}
	listFilterKeys   = []string{"owner_user_id", "content_type"}
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

// List returns one page of media and the total count. gokit rejects an order
// column outside the allow list; here it falls back to the default order, so
// a bad order_by never turns into a 500.
func (r *Repository) List(ctx context.Context, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error) {
	filters := map[string]any{}
	if req.OwnerUserID != "" {
		filters["owner_user_id"] = req.OwnerUserID
	}
	if req.ContentType != "" {
		filters["content_type"] = req.ContentType
	}

	orderBy, direction := req.OrderBy, strings.ToLower(req.OrderDirection)
	if !slices.Contains(listOrderColumns, orderBy) || (direction != "asc" && direction != "desc") {
		orderBy, direction = "", ""
	}

	return r.GetAll(ctx, gokit.BaseParams{
		Search:         req.Search,
		Filters:        filters,
		OrderBy:        orderBy,
		OrderDirection: direction,
		Page:           req.Page,
		Limit:          req.Limit,
		Offset:         req.Offset,
	}, gokit.QueryOptions{
		Search:              gokit.BuildSearchFunc("original_name"),
		AllowedFilters:      listFilterKeys,
		AllowedOrderColumns: listOrderColumns,
		DefaultOrders:       []string{"created_at DESC"},
	})
}
