package servicelocation

import (
	"fmt"
	domainlocation "starter-kit/internal/domain/location"
	interfacelocation "starter-kit/internal/interfaces/location"
)

type LocationService struct{}

func NewLocationService() *LocationService {
	return &LocationService{}
}

func (s *LocationService) GetProvince(year string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_pro?thn=%s", year)
	body, err := fetchResponseBody(url, "province")
	if err != nil {
		return nil, err
	}

	dataMap, err := unmarshalLocationMap(body)
	if err != nil {
		return []domainlocation.Location{{
			Code: "52",
			Name: "NUSA TENGGARA BARAT",
		}}, nil
	}

	return toSortedLocations(dataMap), nil
}

func (s *LocationService) GetCity(year, lvl, pro string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kab?thn=%s&lvl=%s&pro=%s", year, lvl, pro)
	body, err := fetchResponseBody(url, "city")
	if err != nil {
		return nil, err
	}

	dataMap, err := unmarshalLocationMap(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return toSortedLocations(dataMap), nil
}

func (s *LocationService) GetDistrict(year, lvl, pro, kab string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kec?thn=%s&lvl=%s&pro=%s&kab=%s", year, lvl, pro, kab)
	body, err := fetchResponseBody(url, "district")
	if err != nil {
		return nil, err
	}

	dataMap, err := unmarshalLocationMap(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return toSortedLocations(dataMap), nil
}

func (s *LocationService) GetVillage(year, lvl, pro, kab, kec string) ([]domainlocation.Location, error) {
	url := fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_des?thn=%s&lvl=%s&pro=%s&kab=%s&kec=%s", year, lvl, pro, kab, kec)
	body, err := fetchResponseBody(url, "village")
	if err != nil {
		return nil, err
	}

	dataMap, err := unmarshalLocationMap(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return toSortedLocations(dataMap), nil
}

var _ interfacelocation.ServiceLocationInterface = (*LocationService)(nil)
