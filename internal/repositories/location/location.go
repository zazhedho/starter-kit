package repositorylocation

import (
	"context"
	"errors"
	"github.com/zazhedho/gokit"
	domainlocation "starter-kit/internal/domain/location"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Repository is the GORM adapter for the location tables.
type Repository struct {
	db *gorm.DB
}

const (
	locationNameOrder  = "name ASC"
	locationCodeFilter = "code = ? AND deleted_at IS NULL"
)

// NewRepository returns a Repository over db.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListProvinces(ctx context.Context) (ret []domainlocation.Province, err error) {
	err = r.db.WithContext(ctx).Where("deleted_at IS NULL").Order(locationNameOrder).Find(&ret).Error
	return
}

func (r *Repository) ListCitiesByProvince(ctx context.Context, provinceCode string) (ret []domainlocation.City, err error) {
	err = r.db.WithContext(ctx).Where("province_code = ? AND deleted_at IS NULL", provinceCode).Order(locationNameOrder).Find(&ret).Error
	return
}

func (r *Repository) ListDistrictsByCity(ctx context.Context, cityCode string) (ret []domainlocation.District, err error) {
	err = r.db.WithContext(ctx).Where("city_code = ? AND deleted_at IS NULL", cityCode).Order(locationNameOrder).Find(&ret).Error
	return
}

func (r *Repository) ListVillagesByDistrict(ctx context.Context, districtCode string) (ret []domainlocation.Village, err error) {
	err = r.db.WithContext(ctx).Where("district_code = ? AND deleted_at IS NULL", districtCode).Order(locationNameOrder).Find(&ret).Error
	return
}

func (r *Repository) GetProvinceByCode(ctx context.Context, code string) (ret domainlocation.Province, err error) {
	return getByCode[domainlocation.Province](ctx, r.db, code)
}

func (r *Repository) GetCityByCode(ctx context.Context, code string) (ret domainlocation.City, err error) {
	return getByCode[domainlocation.City](ctx, r.db, code)
}

func (r *Repository) GetDistrictByCode(ctx context.Context, code string) (ret domainlocation.District, err error) {
	return getByCode[domainlocation.District](ctx, r.db, code)
}

func getByCode[T any](ctx context.Context, db *gorm.DB, code string) (T, error) {
	var ret T
	err := db.WithContext(ctx).Where(locationCodeFilter, code).First(&ret).Error
	return ret, translateNotFound(err)
}

// translateNotFound maps the ORM's missing-row error to the domain sentinel so
// callers never import the ORM to recognize it.
func translateNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domainlocation.ErrNotFound
	}
	return err
}

func (r *Repository) UpsertProvinces(ctx context.Context, items []domainlocation.Province) error {
	return r.upsert(ctx, "code", items)
}

func (r *Repository) UpsertCities(ctx context.Context, items []domainlocation.City) error {
	return r.upsert(ctx, "code", items)
}

func (r *Repository) UpsertDistricts(ctx context.Context, items []domainlocation.District) error {
	return r.upsert(ctx, "code", items)
}

func (r *Repository) UpsertVillages(ctx context.Context, items []domainlocation.Village) error {
	return r.upsert(ctx, "code", items)
}

func (r *Repository) CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	return r.db.WithContext(ctx).Create(job).Error
}

func (r *Repository) UpdateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	return r.db.WithContext(ctx).Save(job).Error
}

func (r *Repository) GetSyncJobByID(ctx context.Context, id string) (ret domainlocation.SyncJob, err error) {
	err = r.db.WithContext(ctx).Where("id = ?", id).First(&ret).Error
	return ret, translateNotFound(err)
}

func (r *Repository) GetActiveSyncJob(ctx context.Context) (ret domainlocation.SyncJob, err error) {
	err = r.db.WithContext(ctx).
		Where("status IN ?", []string{"queued", "running"}).
		Order("created_at ASC").
		First(&ret).Error
	return ret, translateNotFound(err)
}

func (r *Repository) FailActiveSyncJobs(ctx context.Context, message string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&domainlocation.SyncJob{}).
		Where("status IN ?", []string{"queued", "running"}).
		Updates(map[string]any{
			"status":        "failed",
			"message":       "Location sync interrupted",
			"error_message": message,
			"finished_at":   now,
			"updated_at":    now,
		}).Error
}

func (r *Repository) upsert(ctx context.Context, conflictColumn string, values any) error {
	switch items := values.(type) {
	case []domainlocation.Province:
		prepareUpsertRows(items, func(item *domainlocation.Province) (*string, *time.Time, **time.Time) {
			return &item.ID, &item.CreatedAt, &item.UpdatedAt
		})
		return r.saveUpsert(ctx, conflictColumn, &items, []string{"name", "updated_at", "deleted_at"})
	case []domainlocation.City:
		prepareUpsertRows(items, func(item *domainlocation.City) (*string, *time.Time, **time.Time) {
			return &item.ID, &item.CreatedAt, &item.UpdatedAt
		})
		return r.saveUpsert(ctx, conflictColumn, &items, []string{"province_code", "name", "updated_at", "deleted_at"})
	case []domainlocation.District:
		prepareUpsertRows(items, func(item *domainlocation.District) (*string, *time.Time, **time.Time) {
			return &item.ID, &item.CreatedAt, &item.UpdatedAt
		})
		return r.saveUpsert(ctx, conflictColumn, &items, []string{"city_code", "name", "updated_at", "deleted_at"})
	case []domainlocation.Village:
		prepareUpsertRows(items, func(item *domainlocation.Village) (*string, *time.Time, **time.Time) {
			return &item.ID, &item.CreatedAt, &item.UpdatedAt
		})
		return r.saveUpsert(ctx, conflictColumn, &items, []string{"district_code", "name", "updated_at", "deleted_at"})
	default:
		return nil
	}
}

func (r *Repository) saveUpsert(ctx context.Context, conflictColumn string, values any, updateColumns []string) error {
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: conflictColumn}},
		DoUpdates: clause.AssignmentColumns(updateColumns),
	}).Create(values).Error
}

func prepareUpsertRows[T any](items []T, fields func(*T) (*string, *time.Time, **time.Time)) {
	now := time.Now()
	for i := range items {
		id, createdAt, updatedAt := fields(&items[i])
		if *id == "" {
			*id = gokit.CreateUUID()
		}
		if createdAt.IsZero() {
			*createdAt = now
		}
		*updatedAt = &now
	}
}
