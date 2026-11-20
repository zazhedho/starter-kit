package location

import (
	"sort"
	"strings"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func normalizeKey(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func mapProvinces(rows []domainlocation.Province) []dtolocation.Location {
	locations := make([]dtolocation.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dtolocation.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapCities(rows []domainlocation.City) []dtolocation.Location {
	locations := make([]dtolocation.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dtolocation.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapDistricts(rows []domainlocation.District) []dtolocation.Location {
	locations := make([]dtolocation.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dtolocation.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapVillages(rows []domainlocation.Village) []dtolocation.Location {
	locations := make([]dtolocation.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dtolocation.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func sortProvinces(items []domainlocation.Province) []domainlocation.Province {
	sort.Slice(items, func(i, j int) bool { return normalizeKey(items[i].Name) < normalizeKey(items[j].Name) })
	return items
}

func sortCities(items []domainlocation.City) []domainlocation.City {
	sort.Slice(items, func(i, j int) bool { return normalizeKey(items[i].Name) < normalizeKey(items[j].Name) })
	return items
}

func sortDistricts(items []domainlocation.District) []domainlocation.District {
	sort.Slice(items, func(i, j int) bool { return normalizeKey(items[i].Name) < normalizeKey(items[j].Name) })
	return items
}

func sortVillages(items []domainlocation.Village) []domainlocation.Village {
	sort.Slice(items, func(i, j int) bool { return normalizeKey(items[i].Name) < normalizeKey(items[j].Name) })
	return items
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
