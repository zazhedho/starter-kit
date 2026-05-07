package servicelocation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"
	"strings"
	"time"
)

func (s *LocationService) fetchLocationMap(ctx context.Context, url, entity string) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request: %w", entity, err)
	}

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", entity, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for %s: %d", entity, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response body: %w", entity, err)
	}

	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, fmt.Errorf("failed to decode %s response: %w", entity, err)
	}

	return dataMap, nil
}

func mapProvinces(rows []domainlocation.Province) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapCities(rows []domainlocation.City) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapDistricts(rows []domainlocation.District) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapVillages(rows []domainlocation.Village) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func sortProvinces(items []domainlocation.Province) []domainlocation.Province {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortCities(items []domainlocation.City) []domainlocation.City {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortDistricts(items []domainlocation.District) []domainlocation.District {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortVillages(items []domainlocation.Village) []domainlocation.Village {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func mapSyncJob(job domainlocation.SyncJob) dto.LocationSyncJob {
	return dto.LocationSyncJob{
		ID:            job.ID,
		Status:        job.Status,
		Level:         job.Level,
		Year:          job.Year,
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

func normalizeChildCode(parentCode, code string) string {
	trimmedCode := strings.TrimSpace(code)
	if trimmedCode == "" {
		return ""
	}

	trimmedParent := strings.TrimSpace(parentCode)
	if trimmedParent == "" {
		return trimmedCode
	}

	if strings.HasPrefix(trimmedCode, trimmedParent) && len(trimmedCode) > len(trimmedParent) {
		return trimmedCode
	}

	return trimmedParent + trimmedCode
}

func childCodeCandidates(parentCode, code string) []string {
	trimmedCode := strings.TrimSpace(code)
	if trimmedCode == "" {
		return nil
	}

	candidates := make([]string, 0, 2)
	trimmedParent := strings.TrimSpace(parentCode)
	if trimmedParent != "" && strings.HasPrefix(trimmedCode, trimmedParent) {
		suffix := strings.TrimPrefix(trimmedCode, trimmedParent)
		if suffix != "" {
			candidates = append(candidates, suffix)
		}
	}

	candidates = append(candidates, trimmedCode)

	unique := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		unique = append(unique, candidate)
	}

	return unique
}
