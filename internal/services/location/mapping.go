package location

import (
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func viewProvince(r domainlocation.Province) dtolocation.Location {
	return dtolocation.Location{Code: r.Code, Name: r.Name}
}

func viewCity(r domainlocation.City) dtolocation.Location {
	return dtolocation.Location{Code: r.Code, Name: r.Name}
}

func viewDistrict(r domainlocation.District) dtolocation.Location {
	return dtolocation.Location{Code: r.Code, Name: r.Name}
}

func viewVillage(r domainlocation.Village) dtolocation.Location {
	return dtolocation.Location{Code: r.Code, Name: r.Name}
}

func views[T any](rows []T, view func(T) dtolocation.Location) []dtolocation.Location {
	locations := make([]dtolocation.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, view(row))
	}
	return locations
}

func mapSyncJob(job domainlocation.SyncJob) dtolocation.SyncJob {
	return dtolocation.SyncJob{
		ID:            job.ID,
		Status:        job.Status,
		Level:         job.Level,
		ProvinceCode:  job.ProvinceCode,
		CityCode:      job.CityCode,
		DistrictCode:  job.DistrictCode,
		RequestedBy:   job.RequestedBy,
		Message:       job.Message,
		ErrorMessage:  job.ErrorMessage,
		ProvinceCount: job.ProvinceCount,
		CityCount:     job.CityCount,
		DistrictCount: job.DistrictCount,
		VillageCount:  job.VillageCount,
		StartedAt:     formatTimeISO(job.StartedAt),
		FinishedAt:    formatTimeISO(job.FinishedAt),
		CreatedAt:     job.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     formatTimeISO(job.UpdatedAt),
	}
}

func formatTimeISO(value *time.Time) string {
	if value == nil {
		return ""
	}

	return value.Format(time.RFC3339)
}
