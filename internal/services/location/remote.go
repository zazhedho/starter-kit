package location

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zazhedho/logus"

	domainlocation "starter-kit/internal/domain/location"
)

// maxNameLength is the width of the name columns, in characters.
const maxNameLength = 255

// maxEnvelopeDepth bounds how many {"data": ...} wrappers are unwrapped.
const maxEnvelopeDepth = 3

type locationServiceEnvelope struct {
	Data json.RawMessage `json:"data"`
}

type locationServiceItem struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// entry is one location the Location Service returned, after validation: a code
// stored as is and a name.
type entry struct{ Code, Name string }

func (s *Service) locationServiceURL(path string, query map[string]string) string {
	rawURL := strings.TrimRight(s.baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	values := url.Values{}
	for key, value := range query {
		if strings.TrimSpace(value) != "" {
			values.Set(key, value)
		}
	}
	if encoded := values.Encode(); encoded != "" {
		rawURL += "?" + encoded
	}
	return rawURL
}

// fetchEntries asks the Location Service for one level and returns the valid
// entries that belong to parent, sorted by name then code. parent is empty for
// provinces. Every failure wraps domainlocation.ErrUpstream.
func (s *Service) fetchEntries(ctx context.Context, entity, path string, query map[string]string, parent string) ([]entry, error) {
	body, err := s.getBody(ctx, s.locationServiceURL(path, query), entity)
	if err != nil {
		return nil, err
	}
	pairs, err := decodePairs(body, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode %s response: %w", domainlocation.ErrUpstream, entity, err)
	}

	byCode := make(map[string]string, len(pairs))
	dropped := 0
	for _, p := range pairs {
		code, ok := childCode(parent, strings.TrimSpace(p.Code))
		name := strings.TrimSpace(p.Name)
		if !ok || name == "" || utf8.RuneCountInString(name) > maxNameLength {
			dropped++
			continue
		}
		byCode[code] = name
	}
	if dropped > 0 {
		logus.Logf(logus.LevelWarn, "location: dropped %d invalid or foreign %s items from the location service", dropped, entity)
	}

	entries := make([]entry, 0, len(byCode))
	for code, name := range byCode {
		entries = append(entries, entry{Code: code, Name: name})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		if c := strings.Compare(normalizeKey(a.Name), normalizeKey(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Code, b.Code)
	})
	return entries, nil
}

// getBody performs the GET and returns the body, which is read up to the
// configured cap and no further.
func (s *Service) getBody(ctx context.Context, target, entity string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to prepare %s request: %w", domainlocation.ErrUpstream, entity, err)
	}

	resp, err := s.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch %s: %w", domainlocation.ErrUpstream, entity, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status code for %s: %d", domainlocation.ErrUpstream, entity, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read %s response body: %w", domainlocation.ErrUpstream, entity, err)
	}
	if int64(len(body)) > s.maxResponse {
		return nil, fmt.Errorf("%w: %s response is larger than %d bytes", domainlocation.ErrUpstream, entity, s.maxResponse)
	}
	return body, nil
}

// decodePairs reads either response shape, a {"<code>": "<name>"} object or an
// array of {"code", "name"}, optionally inside {"data": ...}, into one list.
func decodePairs(body []byte, depth int) ([]locationServiceItem, error) {
	var envelope locationServiceEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Data) > 0 && depth < maxEnvelopeDepth {
		return decodePairs(envelope.Data, depth+1)
	}

	var byCode map[string]string
	if err := json.Unmarshal(body, &byCode); err == nil {
		pairs := make([]locationServiceItem, 0, len(byCode))
		for code, name := range byCode {
			pairs = append(pairs, locationServiceItem{Code: code, Name: name})
		}
		return pairs, nil
	}

	var items []locationServiceItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// fetchRows fetches one level and builds its rows.
func fetchRows[T any](ctx context.Context, s *Service, entity, path string, query map[string]string, parent string, build func(entry, time.Time) T) ([]T, error) {
	entries, err := s.fetchEntries(ctx, entity, path, query, parent)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	rows := make([]T, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, build(e, now))
	}
	return rows, nil
}

func (s *Service) fetchProvinces(ctx context.Context) ([]domainlocation.Province, error) {
	return fetchRows(ctx, s, "province", "/api/locations/provinces", nil, "",
		func(e entry, now time.Time) domainlocation.Province {
			return domainlocation.Province{Code: e.Code, Name: e.Name, CreatedAt: now}
		})
}

func (s *Service) fetchCities(ctx context.Context, provinceCode string) ([]domainlocation.City, error) {
	return fetchRows(ctx, s, "city", "/api/locations/regencies", map[string]string{
		"province_code": provinceCode,
		"code_format":   "short",
	}, provinceCode, func(e entry, now time.Time) domainlocation.City {
		return domainlocation.City{Code: e.Code, ProvinceCode: provinceCode, Name: e.Name, CreatedAt: now}
	})
}

func (s *Service) fetchDistricts(ctx context.Context, provinceCode, cityCode string) ([]domainlocation.District, error) {
	return fetchRows(ctx, s, "district", "/api/locations/districts", map[string]string{
		"province_code": provinceCode,
		"regency_code":  childCodeParam(provinceCode, cityCode),
		"code_format":   "short",
	}, cityCode, func(e entry, now time.Time) domainlocation.District {
		return domainlocation.District{Code: e.Code, CityCode: cityCode, Name: e.Name, CreatedAt: now}
	})
}

func (s *Service) fetchVillages(ctx context.Context, provinceCode, cityCode, districtCode string) ([]domainlocation.Village, error) {
	return fetchRows(ctx, s, "village", "/api/locations/villages", map[string]string{
		"province_code": provinceCode,
		"regency_code":  childCodeParam(provinceCode, cityCode),
		"district_code": childCodeParam(cityCode, districtCode),
		"code_format":   "short",
	}, districtCode, func(e entry, now time.Time) domainlocation.Village {
		return domainlocation.Village{Code: e.Code, DistrictCode: districtCode, Name: e.Name, CreatedAt: now}
	})
}

func normalizeKey(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
