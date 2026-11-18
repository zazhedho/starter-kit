package location

import (
	"context"

	dtolocation "starter-kit/internal/dto/location"
)

// Service is what the location handlers call. The concrete service lives in
// internal/services/location; the router wires it in.
type Service interface {
	GetProvince(ctx context.Context) ([]dtolocation.Location, error)
	GetCity(ctx context.Context, provinceCode string) ([]dtolocation.Location, error)
	GetDistrict(ctx context.Context, cityCode string) ([]dtolocation.Location, error)
	GetVillage(ctx context.Context, districtCode string) ([]dtolocation.Location, error)
	StartSync(ctx context.Context, req dtolocation.SyncRequest, requestedBy string) (dtolocation.SyncJob, error)
	GetSyncJob(ctx context.Context, id string) (dtolocation.SyncJob, error)
}
