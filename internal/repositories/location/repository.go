package location

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	domainlocation "starter-kit/internal/domain/location"
)

type Repository struct {
	db *gorm.DB
}

const (
	locationNameOrder  = "name ASC"
	locationCodeFilter = "code = ? AND deleted_at IS NULL"
)

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListProvinces(ctx context.Context) ([]domainlocation.Province, error) {
	var ret []domainlocation.Province
	err := r.db.WithContext(ctx).Where("deleted_at IS NULL").Order(locationNameOrder).Find(&ret).Error
	return ret, err
}

func (r *Repository) ListCitiesByProvince(ctx context.Context, provinceCode string) ([]domainlocation.City, error) {
	var ret []domainlocation.City
	err := r.db.WithContext(ctx).Where("province_code = ? AND deleted_at IS NULL", provinceCode).Order(locationNameOrder).Find(&ret).Error
	return ret, err
}

func (r *Repository) ListDistrictsByCity(ctx context.Context, cityCode string) ([]domainlocation.District, error) {
	var ret []domainlocation.District
	err := r.db.WithContext(ctx).Where("city_code = ? AND deleted_at IS NULL", cityCode).Order(locationNameOrder).Find(&ret).Error
	return ret, err
}

func (r *Repository) ListVillagesByDistrict(ctx context.Context, districtCode string) ([]domainlocation.Village, error) {
	var ret []domainlocation.Village
	err := r.db.WithContext(ctx).Where("district_code = ? AND deleted_at IS NULL", districtCode).Order(locationNameOrder).Find(&ret).Error
	return ret, err
}

func (r *Repository) GetProvinceByCode(ctx context.Context, code string) (domainlocation.Province, error) {
	return getByCode[domainlocation.Province](ctx, r.db, code)
}

func (r *Repository) GetCityByCode(ctx context.Context, code string) (domainlocation.City, error) {
	return getByCode[domainlocation.City](ctx, r.db, code)
}

func (r *Repository) GetDistrictByCode(ctx context.Context, code string) (domainlocation.District, error) {
	return getByCode[domainlocation.District](ctx, r.db, code)
}

func getByCode[T any](ctx context.Context, db *gorm.DB, code string) (T, error) {
	var ret T
	err := db.WithContext(ctx).Where(locationCodeFilter, code).First(&ret).Error
	return ret, translateNotFound(err)
}

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

// ux_location_sync_jobs_one_active allows one row in these states.
var activeStatuses = []string{"queued", "running"}

func (r *Repository) CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	err := r.db.WithContext(ctx).Omit("heartbeat_at").Create(job).Error
	if isUniqueViolation(err) {
		return domainlocation.ErrSyncRunning
	}
	return err
}

func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "23505"
}

// heartbeat_at uses the database clock: instances disagree about time and compare heartbeats across each other.
var dbNow = gorm.Expr("now()")

func (r *Repository) StartSyncJob(ctx context.Context, id, owner string, at time.Time) error {
	return r.updateOwned(ctx, id, owner, []string{"queued"}, map[string]any{
		"status":       "running",
		"message":      "Location sync is running",
		"started_at":   at,
		"updated_at":   at,
		"heartbeat_at": dbNow,
	})
}

func (r *Repository) SaveSyncProgress(ctx context.Context, id, owner string, p domainlocation.SyncProgress, at time.Time) error {
	return r.updateOwned(ctx, id, owner, activeStatuses, map[string]any{
		"message":        p.Message,
		"province_count": p.ProvinceCount,
		"city_count":     p.CityCount,
		"district_count": p.DistrictCount,
		"village_count":  p.VillageCount,
		"updated_at":     at,
		"heartbeat_at":   dbNow,
	})
}

func (r *Repository) TouchSyncJob(ctx context.Context, id, owner string) error {
	return r.updateOwned(ctx, id, owner, activeStatuses, map[string]any{"heartbeat_at": dbNow})
}

func (r *Repository) FinishSyncJob(ctx context.Context, id, owner string, f domainlocation.SyncFinish, at time.Time) error {
	return r.updateOwned(ctx, id, owner, activeStatuses, map[string]any{
		"status":        f.Status,
		"message":       f.Message,
		"error_message": f.ErrorMessage,
		"finished_at":   at,
		"updated_at":    at,
		"heartbeat_at":  dbNow,
	})
}

// No match means the job was finished or taken over, reported as ErrNotFound.
func (r *Repository) updateOwned(ctx context.Context, id, owner string, statuses []string, columns map[string]any) error {
	res := r.db.WithContext(ctx).Model(&domainlocation.SyncJob{}).
		Where("id = ? AND owner_instance_id = ? AND status IN ?", id, owner, statuses).
		Updates(columns)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return domainlocation.ErrNotFound
	}
	return nil
}

func (r *Repository) GetSyncJobByID(ctx context.Context, id string) (domainlocation.SyncJob, error) {
	var ret domainlocation.SyncJob
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&ret).Error
	return ret, translateNotFound(err)
}

func (r *Repository) GetActiveSyncJob(ctx context.Context) (domainlocation.SyncJob, error) {
	var ret domainlocation.SyncJob
	err := r.db.WithContext(ctx).
		Where("status IN ?", activeStatuses).
		Order("created_at ASC").
		First(&ret).Error
	return ret, translateNotFound(err)
}

func (r *Repository) FailStaleSyncJobs(ctx context.Context, staleAfter time.Duration, now time.Time, message string) error {
	return r.db.WithContext(ctx).Model(&domainlocation.SyncJob{}).
		Where("status IN ? AND heartbeat_at < now() - make_interval(secs => ?)", activeStatuses, staleAfter.Seconds()).
		Updates(map[string]any{
			"status":        "failed",
			"message":       "Location sync interrupted",
			"error_message": message,
			"finished_at":   now,
			"updated_at":    now,
		}).Error
}

func (r *Repository) upsert(ctx context.Context, conflictColumn string, values any) error {
	if rv := reflect.ValueOf(values); rv.Kind() == reflect.Slice && rv.Len() == 0 {
		return nil // gorm refuses to insert an empty slice
	}
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
