package location

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	domainlocation "starter-kit/internal/domain/location"
)

func newLocationFallbackService(t *testing.T) *Service {
	t.Helper()
	repo := &locationRepoTestDouble{
		city:     domainlocation.City{Code: "1671", ProvinceCode: "16", Name: "Palembang"},
		district: domainlocation.District{Code: "167101", CityCode: "1671", Name: "Ilir Timur I"},
	}
	svc := newTestService(t, repo, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case strings.Contains(req.URL.Path, "/api/locations/provinces"):
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"16","name":"Sumatera Selatan"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/regencies"):
			if got := req.URL.Query().Get("province_code"); got != "16" {
				t.Fatalf("expected province_code 16, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"71","name":"Kota Palembang"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/districts"):
			if got := req.URL.Query().Get("regency_code"); got != "71" {
				t.Fatalf("expected regency_code 71, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","name":"Ilir Timur I"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/villages"):
			if got := req.URL.Query().Get("district_code"); got != "01" {
				t.Fatalf("expected district_code 01, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"1001","name":"Sungai Pangeran"}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	}))
	return svc
}

func TestLocationServiceGetProvinceFallsBackToLocationService(t *testing.T) {
	provinces, err := newLocationFallbackService(t).GetProvince(context.Background())
	if err != nil || len(provinces) != 1 || provinces[0].Code != "16" {
		t.Fatalf("province fallback failed: rows=%+v err=%v", provinces, err)
	}
}

func TestLocationServiceGetCityFallsBackToLocationService(t *testing.T) {
	cities, err := newLocationFallbackService(t).GetCity(context.Background(), "16")
	if err != nil || len(cities) != 1 || cities[0].Code != "1671" {
		t.Fatalf("city fallback failed: rows=%+v err=%v", cities, err)
	}
}

func TestLocationServiceGetDistrictFallsBackToLocationService(t *testing.T) {
	districts, err := newLocationFallbackService(t).GetDistrict(context.Background(), "1671")
	if err != nil || len(districts) != 1 || districts[0].Code != "167101" {
		t.Fatalf("district fallback failed: rows=%+v err=%v", districts, err)
	}
}

func TestLocationServiceGetVillageFallsBackToLocationService(t *testing.T) {
	villages, err := newLocationFallbackService(t).GetVillage(context.Background(), "167101")
	if err != nil || len(villages) != 1 || villages[0].Code != "1671011001" {
		t.Fatalf("village fallback failed: rows=%+v err=%v", villages, err)
	}
}

func TestFetchLocationMapHandlesHTTPResponses(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"11","full_code":"11","name":"Aceh","level":"province"}]}`)),
			Header:     make(http.Header),
		}, nil
	}))
	got, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got["11"] != "Aceh" {
		t.Fatalf("unexpected location map: %+v", got)
	}

	svc.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province"); err == nil {
		t.Fatal("expected status error")
	}

	svc.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	if _, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province"); err == nil {
		t.Fatal("expected transport error")
	}

	svc.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{`)),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province"); err == nil {
		t.Fatal("expected decode error")
	}
}

func newScopedLocationSyncService(t *testing.T, repo *locationRepoTestDouble) *Service {
	t.Helper()
	return newTestService(t, repo, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{}`
		switch {
		case strings.Contains(req.URL.Path, "/api/locations/provinces"):
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"31","full_code":"31","name":"DKI Jakarta","level":"province"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/regencies"):
			if got := req.URL.Query().Get("province_code"); got != "31" {
				t.Fatalf("expected province_code 31, got %q", got)
			}
			if got := req.URL.Query().Get("code_format"); got != "short" {
				t.Fatalf("expected short code format, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"71","full_code":"31.71","name":"Jakarta Selatan","level":"regency","parent_code":"31"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/districts"):
			if got := req.URL.Query().Get("regency_code"); got != "71" {
				t.Fatalf("expected regency_code 71, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","full_code":"31.71.01","name":"Tebet","level":"district","parent_code":"31.71"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/villages"):
			if got := req.URL.Query().Get("district_code"); got != "01" {
				t.Fatalf("expected district_code 01, got %q", got)
			}
			body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","full_code":"31.71.01.0001","name":"Tebet Barat","level":"village","parent_code":"31.71.01"}]}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	}))
}

func TestLocationFetchScopedLevelsNormalizeCodes(t *testing.T) {
	svc := newScopedLocationSyncService(t, &locationRepoTestDouble{})
	ctx := context.Background()
	cities, err := svc.fetchCities(ctx, "31")
	if err != nil || len(cities) != 1 || cities[0].Code != "3171" {
		t.Fatalf("fetch cities: cities=%+v err=%v", cities, err)
	}
	districts, err := svc.fetchDistricts(ctx, "31", "3171")
	if err != nil || len(districts) != 1 || districts[0].Code != "317101" {
		t.Fatalf("fetch districts: districts=%+v err=%v", districts, err)
	}
	villages, err := svc.fetchVillages(ctx, "31", "3171", "317101")
	if err != nil || len(villages) != 1 || villages[0].Code != "31710101" {
		t.Fatalf("fetch villages: villages=%+v err=%v", villages, err)
	}
}
