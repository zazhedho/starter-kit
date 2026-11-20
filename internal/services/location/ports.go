package location

import (
	"context"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

// Repository is the persistence the service needs; the GORM adapter satisfies it
// and maps a missing row to domainlocation.ErrNotFound.
//
// The sync job methods with an owner act only on a job of that service instance
// that is still queued or running, and answer ErrNotFound when none matches:
// the job finished or another instance took it over.
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

	// CreateSyncJob stores a queued job and answers ErrSyncRunning when another
	// job is queued or running.
	CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error
	GetSyncJobByID(ctx context.Context, id string) (domainlocation.SyncJob, error)
	GetActiveSyncJob(ctx context.Context) (domainlocation.SyncJob, error)
	StartSyncJob(ctx context.Context, id, owner string, at time.Time) error
	SaveSyncProgress(ctx context.Context, id, owner string, p domainlocation.SyncProgress, at time.Time) error
	TouchSyncJob(ctx context.Context, id, owner string, at time.Time) error
	FinishSyncJob(ctx context.Context, id, owner string, f domainlocation.SyncFinish, at time.Time) error
	// FailStaleSyncJobs fails every queued or running job whose heartbeat is
	// older than cutoff.
	FailStaleSyncJobs(ctx context.Context, cutoff, now time.Time, message string) error
}

// Cache is the read-through cache. Implementations must treat every failure as
// a miss (Get) or no-op (Set, DeleteKeys): it is an optimisation, not a dependency.
type Cache interface {
	Get(ctx context.Context, key string) ([]dtolocation.Location, bool)
	Set(ctx context.Context, key string, locations []dtolocation.Location, ttl time.Duration)
	// DeleteKeys removes every key that starts with prefix.
	DeleteKeys(ctx context.Context, prefix string)
}

// noopCache is the cache NewService installs when Options.Cache is nil: every
// lookup misses.
type noopCache struct{}

func (noopCache) Get(context.Context, string) ([]dtolocation.Location, bool)         { return nil, false }
func (noopCache) Set(context.Context, string, []dtolocation.Location, time.Duration) {}
func (noopCache) DeleteKeys(context.Context, string)                                 {}
