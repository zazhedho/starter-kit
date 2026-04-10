package interfacelocation

import domainlocation "starter-kit/internal/domain/location"

type RepoLocationInterface interface {
	ListProvinces() ([]domainlocation.Province, error)
	ListCitiesByProvince(provinceCode string) ([]domainlocation.City, error)
	ListDistrictsByCity(cityCode string) ([]domainlocation.District, error)
	ListVillagesByDistrict(districtCode string) ([]domainlocation.Village, error)
	GetProvinceByCode(code string) (domainlocation.Province, error)
	GetCityByCode(code string) (domainlocation.City, error)
	GetDistrictByCode(code string) (domainlocation.District, error)
	UpsertProvinces(items []domainlocation.Province) error
	UpsertCities(items []domainlocation.City) error
	UpsertDistricts(items []domainlocation.District) error
	UpsertVillages(items []domainlocation.Village) error
	CreateSyncJob(job *domainlocation.SyncJob) error
	UpdateSyncJob(job *domainlocation.SyncJob) error
	GetSyncJobByID(id string) (domainlocation.SyncJob, error)
	GetActiveSyncJob() (domainlocation.SyncJob, error)
	FailActiveSyncJobs(message string) error
}
