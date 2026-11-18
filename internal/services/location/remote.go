package location

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	domainlocation "starter-kit/internal/domain/location"
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

func (s *Service) fetchProvinces(ctx context.Context, year string) ([]domainlocation.Province, error) {
	_ = year
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/provinces", nil), "province")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.Province, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.Province{
			Code:      code,
			Name:      name,
			CreatedAt: now,
		})
	}

	return sortProvinces(items), nil
}

func (s *Service) fetchCities(ctx context.Context, year, provinceCode string) ([]domainlocation.City, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/regencies", map[string]string{
		"province_code": cleanProvinceCode,
		"code_format":   "short",
	}), "city")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.City, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.City{
			Code:         normalizeChildCode(cleanProvinceCode, code),
			ProvinceCode: cleanProvinceCode,
			Name:         name,
			CreatedAt:    now,
		})
	}

	return sortCities(items), nil
}

func (s *Service) fetchDistricts(ctx context.Context, year, provinceCode, cityCode string) ([]domainlocation.District, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	cleanCityCode := normalizeCodeSegment(cityCode)
	cityParam := childCodeParam(cleanProvinceCode, cleanCityCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/districts", map[string]string{
		"province_code": cleanProvinceCode,
		"regency_code":  cityParam,
		"code_format":   "short",
	}), "district")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.District, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.District{
			Code:      normalizeChildCode(cleanCityCode, code),
			CityCode:  cleanCityCode,
			Name:      name,
			CreatedAt: now,
		})
	}

	return sortDistricts(items), nil
}

func (s *Service) fetchVillages(ctx context.Context, year, provinceCode, cityCode, districtCode string) ([]domainlocation.Village, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	cleanCityCode := normalizeCodeSegment(cityCode)
	cleanDistrictCode := normalizeCodeSegment(districtCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/villages", map[string]string{
		"province_code": cleanProvinceCode,
		"regency_code":  childCodeParam(cleanProvinceCode, cleanCityCode),
		"district_code": childCodeParam(cleanCityCode, cleanDistrictCode),
		"code_format":   "short",
	}), "village")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.Village, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.Village{
			Code:         normalizeChildCode(cleanDistrictCode, code),
			DistrictCode: cleanDistrictCode,
			Name:         name,
			CreatedAt:    now,
		})
	}

	return sortVillages(items), nil
}
