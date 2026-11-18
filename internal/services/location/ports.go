package servicelocation

import (
	"context"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"
)

// Repository is the persistence the location service needs. The GORM adapter
// in internal/repositories/location satisfies it by method set and translates
// a missing row into domainlocation.ErrNotFound.
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
	UpdateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error
	GetSyncJobByID(ctx context.Context, id string) (domainlocation.SyncJob, error)
	GetActiveSyncJob(ctx context.Context) (domainlocation.SyncJob, error)
	FailActiveSyncJobs(ctx context.Context, message string) error
}

// Cache is the read-through cache the location service uses. Implementations
// live in internal/infrastructure/cache and must treat every failure as a miss
// (Get) or a no-op (Set, DeleteKeys): the cache is an optimisation, never a
// dependency.
type Cache interface {
	Get(ctx context.Context, key string) ([]dto.Location, bool)
	Set(ctx context.Context, key string, locations []dto.Location, ttl time.Duration)
	// DeleteKeys removes every key that starts with prefix.
	DeleteKeys(ctx context.Context, prefix string)
}

// noopCache stands in when no Cache is configured: every lookup misses.
type noopCache struct{}

func (noopCache) Get(context.Context, string) ([]dto.Location, bool)         { return nil, false }
func (noopCache) Set(context.Context, string, []dto.Location, time.Duration) {}
func (noopCache) DeleteKeys(context.Context, string)                         {}

func (s *LocationService) cacheOrNoop() Cache {
	if s.cache == nil {
		return noopCache{}
	}
	return s.cache
}
