package handlerlocation

import (
	"context"

	"starter-kit/internal/dto"
)

// Service is what the location handlers call. The concrete service lives in
// internal/services/location; the router wires it in.
type Service interface {
	GetProvince(ctx context.Context) ([]dto.Location, error)
	GetCity(ctx context.Context, provinceCode string) ([]dto.Location, error)
	GetDistrict(ctx context.Context, cityCode string) ([]dto.Location, error)
	GetVillage(ctx context.Context, districtCode string) ([]dto.Location, error)
	StartSync(ctx context.Context, req dto.SyncLocationRequest) (dto.LocationSyncJob, error)
	GetSyncJob(ctx context.Context, id string) (dto.LocationSyncJob, error)
}
