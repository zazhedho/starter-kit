package location

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
	"strings"
	"time"
)

type locationServiceEnvelope struct {
	Data json.RawMessage `json:"data"`
}

type locationServiceItem struct {
	Code     string `json:"code"`
	FullCode string `json:"full_code"`
	Name     string `json:"name"`
}

func (s *Service) locationServiceURL(path string, query map[string]string) string {
	baseURL := strings.TrimRight(s.baseURL, "/")
	endpoint := strings.TrimLeft(path, "/")
	rawURL := baseURL + "/" + endpoint
	if len(query) == 0 {
		return rawURL
	}

	values := url.Values{}
	for key, value := range query {
		if strings.TrimSpace(value) == "" {
			continue
		}
		values.Set(key, value)
	}
	if encoded := values.Encode(); encoded != "" {
		rawURL += "?" + encoded
	}
	return rawURL
}

func (s *Service) fetchLocationMap(ctx context.Context, url, entity string) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request: %w", entity, err)
	}

	resp, err := s.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", entity, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for %s: %d", entity, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response body: %w", entity, err)
	}

	dataMap, err := decodeLocationMap(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s response: %w", entity, err)
	}

	return dataMap, nil
}

func (s *Service) setLocationCache(ctx context.Context, cacheKey string, locations []dtolocation.Location) {
	// A non-positive TTL would store the entry without expiry; skip instead.
	if len(locations) == 0 || s.cacheTTL <= 0 {
		return
	}
	s.cache.Set(ctx, cacheKey, locations, s.cacheTTL)
}

func decodeLocationMap(body []byte) (map[string]string, error) {
	var envelope locationServiceEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Data) > 0 {
		return decodeLocationMap(envelope.Data)
	}

	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err == nil {
		return dataMap, nil
	}

	var items []locationServiceItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}

	dataMap = make(map[string]string, len(items))
	for _, item := range items {
		code := normalizeCodeSegment(item.Code)
		name := strings.TrimSpace(item.Name)
		if code == "" || name == "" {
			continue
		}
		dataMap[code] = name
	}
	return dataMap, nil
}

// normalizeKey is the comparison form of a name: trimmed and lower-cased.
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
	trimmedCode := normalizeCodeSegment(code)
	if trimmedCode == "" {
		return ""
	}

	trimmedParent := normalizeCodeSegment(parentCode)
	if trimmedParent == "" {
		return trimmedCode
	}

	if strings.HasPrefix(trimmedCode, trimmedParent) && len(trimmedCode) > len(trimmedParent) {
		return trimmedCode
	}

	return trimmedParent + trimmedCode
}

func childCodeParam(parentCode, code string) string {
	candidates := childCodeCandidates(parentCode, code)
	if len(candidates) == 0 {
		return normalizeCodeSegment(code)
	}
	return candidates[0]
}

func childCodeCandidates(parentCode, code string) []string {
	trimmedCode := normalizeCodeSegment(code)
	if trimmedCode == "" {
		return nil
	}

	candidates := make([]string, 0, 2)
	trimmedParent := normalizeCodeSegment(parentCode)
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

func normalizeCodeSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return value
	}
	return b.String()
}
