package location

import (
	"context"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

type Repository interface {
	ListProvinces(ctx context.Context) ([]domainlocation.Province, error)
	ListCitiesByProvince(ctx context.Context, provinceCode string) ([]domainlocation.City, error)
	ListDistrictsByCity(ctx context.Context, cityCode string) ([]domainlocation.District, error)
	ListVillagesByDistrict(ctx context.Context, districtCode string) ([]domainlocation.Village, error)
	GetProvinceByCode(ctx context.Context, code string) (domainlocation.Province, error)
	GetCityByCode(ctx context.Context, code string) (domainlocation.City, error)
	GetDistrictByCode(ctx context.Context, code string) (domainlocation.District, error)
	UpsertProvinces(ctx context.Context, items []domainlocation.Province) error
	UpsertCities(ctx context.Context, items []domainlocation.City) error
	UpsertDistricts(ctx context.Context, items []domainlocation.District) error
	UpsertVillages(ctx context.Context, items []domainlocation.Village) error

	CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error
	GetSyncJobByID(ctx context.Context, id string) (domainlocation.SyncJob, error)
	GetActiveSyncJob(ctx context.Context) (domainlocation.SyncJob, error)
	StartSyncJob(ctx context.Context, id, owner string, at time.Time) error
	SaveSyncProgress(ctx context.Context, id, owner string, p domainlocation.SyncProgress, at time.Time) error
	TouchSyncJob(ctx context.Context, id, owner string) error
	FinishSyncJob(ctx context.Context, id, owner string, f domainlocation.SyncFinish, at time.Time) error
	FailStaleSyncJobs(ctx context.Context, staleAfter time.Duration, now time.Time, message string) error
}

// Cache implementations treat every failure as a miss (Get) or a no-op (Set, DeleteKeys).
type Cache interface {
	Get(ctx context.Context, key string) ([]dtolocation.Location, bool)
	Set(ctx context.Context, key string, locations []dtolocation.Location, ttl time.Duration)
	DeleteKeys(ctx context.Context, prefix string)
}

type noopCache struct{}

func (noopCache) Get(context.Context, string) ([]dtolocation.Location, bool) { return nil, false }
func (noopCache) Set(context.Context, string, []dtolocation.Location, time.Duration) {
	// Nothing is cached.
}

func (noopCache) DeleteKeys(context.Context, string) {
	// Nothing is cached, so nothing to delete.
}
