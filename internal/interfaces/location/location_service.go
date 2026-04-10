package interfacelocation

import "starter-kit/internal/dto"

type ServiceLocationInterface interface {
	GetProvince() ([]dto.Location, error)
	GetCity(provinceCode string) ([]dto.Location, error)
	GetDistrict(cityCode string) ([]dto.Location, error)
	GetVillage(districtCode string) ([]dto.Location, error)
	StartSync(req dto.SyncLocationRequest, requestedByUserID string) (dto.LocationSyncJob, error)
	GetSyncJob(id string) (dto.LocationSyncJob, error)
}
