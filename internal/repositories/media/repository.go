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

// maxListLimit is the one cap on the page size of a media list; gokit applies
// it to every request, and PageSize reports the result.
const maxListLimit = 100

var (
	listOrderColumns = []string{"created_at", "size", "original_name"}
	listFilterKeys   = []string{"owner_user_id", "content_type"}
)

// Repository is the GORM adapter for the media table. It embeds the generic
// gokit repository and overrides GetByID and Delete to translate the not-found
// error into the domain error.
type Repository struct {
	*gokit.Repository[domainmedia.Media]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainmedia.Media](db)}
}

// GetByID shadows the embedded generic lookup to translate the ORM's
// missing-row error into domainmedia.ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, id string) (domainmedia.Media, error) {
	media, err := r.Repository.GetByID(ctx, id)
	if errors.Is(err, gokit.ErrNotFound) {
		return domainmedia.Media{}, domainmedia.ErrNotFound
	}
	return media, err
}

// Delete shadows the embedded generic delete: gokit answers ErrNotFound when no
// row matched (for example a concurrent delete), which becomes
// domainmedia.ErrNotFound, so the handler answers 404.
func (r *Repository) Delete(ctx context.Context, id string) error {
	err := r.Repository.Delete(ctx, id)
	if errors.Is(err, gokit.ErrNotFound) {
		return domainmedia.ErrNotFound
	}
	return err
}

// List returns one page of media and the total. An order outside the allow list
// falls back to created_at DESC, and id is the last sort key so pages are stable.
func (r *Repository) List(ctx context.Context, req dtomedia.ListRequest) (dtomedia.ListResult, error) {
	filters := map[string]any{}
	if req.OwnerUserID != "" {
		filters["owner_user_id"] = req.OwnerUserID
	}
	if req.ContentType != "" {
		filters["content_type"] = req.ContentType
	}

	orderBy, direction := req.OrderBy, strings.ToUpper(req.OrderDirection)
	if !slices.Contains(listOrderColumns, orderBy) || (direction != "ASC" && direction != "DESC") {
		orderBy, direction = "created_at", "DESC"
	}

	// gokit appends DefaultOrders only when the params carry no explicit
	// order, so the chosen order goes through DefaultOrders to get the
	// tie-breaker after it.
	params := gokit.BaseParams{
		Search:  req.Search,
		Filters: filters,
		Page:    req.Page,
		Limit:   req.Limit,
	}
	opts := gokit.QueryOptions{
		Search:         gokit.BuildSearchFunc("original_name"),
		AllowedFilters: listFilterKeys,
		DefaultOrders:  []string{orderBy + " " + direction, "id " + direction},
		MaxLimit:       maxListLimit,
	}
	items, total, err := r.GetAll(ctx, params, opts)
	if err != nil {
		return dtomedia.ListResult{}, err
	}
	return dtomedia.ListResult{Items: items, Total: total, Limit: opts.PageSize(params)}, nil
}
