package servicelocation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	domainlocation "starter-kit/internal/domain/location"
	interfacelocation "starter-kit/internal/interfaces/location"
)

type LocationService struct{}

func NewLocationService() *LocationService {
	return &LocationService{}
}

func (s *LocationService) GetProvince(year string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_pro?thn=%s", year)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch province: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse as map[string]string
	var dataMap map[string]string
	provinces := make([]domainlocation.Location, 0, len(dataMap))
	if err := json.Unmarshal(body, &dataMap); err != nil {
		provinces = append(provinces, domainlocation.Location{
			Code: "52",
			Name: "NUSA TENGGARA BARAT",
		})
	}

	// Convert map to slice
	for code, name := range dataMap {
		provinces = append(provinces, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	// Sort by name in ascending order
	sort.Slice(provinces, func(i, j int) bool {
		return provinces[i].Name < provinces[j].Name
	})

	return provinces, nil
}

func (s *LocationService) GetCity(year, lvl, pro string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kab?thn=%s&lvl=%s&pro=%s", year, lvl, pro)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch city: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse as map[string]string
	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert map to slice
	cities := make([]domainlocation.Location, 0, len(dataMap))
	for code, name := range dataMap {
		cities = append(cities, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	// Sort by name in ascending order
	sort.Slice(cities, func(i, j int) bool {
		return cities[i].Name < cities[j].Name
	})

	return cities, nil
}

func (s *LocationService) GetDistrict(year, lvl, pro, kab string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kec?thn=%s&lvl=%s&pro=%s&kab=%s", year, lvl, pro, kab)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch district: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse as map[string]string
	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Convert map to slice
	districts := make([]domainlocation.Location, 0, len(dataMap))
	for code, name := range dataMap {
		districts = append(districts, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	// Sort by name in ascending order
	sort.Slice(districts, func(i, j int) bool {
		return districts[i].Name < districts[j].Name
	})

	return districts, nil
}

func (s *LocationService) GetVillage(year, lvl, pro, kab, kec string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_des?thn=%s&lvl=%s&pro=%s&kab=%s&kec=%s", year, lvl, pro, kab, kec)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch village: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	villages := make([]domainlocation.Location, 0, len(dataMap))
	for code, name := range dataMap {
		villages = append(villages, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	sort.Slice(villages, func(i, j int) bool {
		return villages[i].Name < villages[j].Name
	})

	return villages, nil
}

var _ interfacelocation.ServiceLocationInterface = (*LocationService)(nil)
