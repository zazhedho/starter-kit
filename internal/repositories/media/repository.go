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

const maxListLimit = 100

var (
	listOrderColumns = []string{"created_at", "size", "original_name"}
	listFilterKeys   = []string{"owner_user_id", "content_type"}
)

type Repository struct {
	*gokit.Repository[domainmedia.Media]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainmedia.Media](db)}
}

func (r *Repository) GetByID(ctx context.Context, id string) (domainmedia.Media, error) {
	media, err := r.Repository.GetByID(ctx, id)
	if errors.Is(err, gokit.ErrNotFound) {
		return domainmedia.Media{}, domainmedia.ErrNotFound
	}
	return media, err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	err := r.Repository.Delete(ctx, id)
	if errors.Is(err, gokit.ErrNotFound) {
		return domainmedia.ErrNotFound
	}
	return err
}

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

	// gokit appends DefaultOrders only when no explicit order is set, so the chosen order goes through
	// DefaultOrders to get the tie-breaker.
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
