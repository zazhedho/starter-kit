package location

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func fallbackRepo() *locationRepoTestDouble {
	return &locationRepoTestDouble{
		knownProvinces: map[string]domainlocation.Province{"16": {Code: "16", Name: "Sumatera Selatan"}},
		knownCities:    map[string]domainlocation.City{"1671": {Code: "1671", ProvinceCode: "16", Name: "Palembang"}},
		knownDistricts: map[string]domainlocation.District{"167101": {Code: "167101", CityCode: "1671", Name: "Ilir Timur I"}},
	}
}

func fallbackUpstream(t *testing.T) *upstream {
	t.Helper()
	return &upstream{handle: func(req *http.Request) *http.Response {
		switch {
		case strings.Contains(req.URL.Path, "/api/locations/provinces"):
			return okResponse(`{"data":[{"code":"16","name":"Sumatera Selatan"}]}`)
		case strings.Contains(req.URL.Path, "/api/locations/regencies"):
			return okResponse(`{"data":[{"code":"71","name":"Kota Palembang"}]}`)
		case strings.Contains(req.URL.Path, "/api/locations/districts"):
			return okResponse(`{"data":[{"code":"01","name":"Ilir Timur I"}]}`)
		case strings.Contains(req.URL.Path, "/api/locations/villages"):
			return okResponse(`{"data":[{"code":"1001","name":"Sungai Pangeran"}]}`)
		}
		return okResponse(`{}`)
	}}
}

func TestAnEmptyLevelIsFilledFromTheLocationService(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		read     func(*Service) ([]string, error)
		wantCode string
		upserted func(*locationRepoTestDouble) int
	}{
		{"province", func(s *Service) ([]string, error) { return codesOf(s.GetProvince(ctx)) }, "16",
			func(r *locationRepoTestDouble) int { return r.upsertProvinceCount }},
		{"city", func(s *Service) ([]string, error) { return codesOf(s.GetCity(ctx, "16")) }, "1671",
			func(r *locationRepoTestDouble) int { return r.upsertCityCount }},
		{"district", func(s *Service) ([]string, error) { return codesOf(s.GetDistrict(ctx, "1671")) }, "167101",
			func(r *locationRepoTestDouble) int { return r.upsertDistrictCount }},
		{"village", func(s *Service) ([]string, error) { return codesOf(s.GetVillage(ctx, "167101")) }, "1671011001",
			func(r *locationRepoTestDouble) int { return r.upsertVillageCount }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := fallbackRepo()
			up := fallbackUpstream(t)
			got, err := c.read(newTestService(t, repo, up))
			if err != nil || len(got) != 1 || got[0] != c.wantCode {
				t.Fatalf("got %v, %v, want [%s]", got, err, c.wantCode)
			}
			if up.calls() != 1 || c.upserted(repo) != 1 {
				t.Fatalf("upstream calls = %d, rows stored = %d, want 1 and 1", up.calls(), c.upserted(repo))
			}
		})
	}
}

func codesOf(locations []dtolocation.Location, err error) ([]string, error) {
	out := make([]string, 0, len(locations))
	for _, l := range locations {
		out = append(out, l.Code)
	}
	return out, err
}

func TestAnUnknownParentIsNotFoundWithoutCallingTheLocationService(t *testing.T) {
	ctx := context.Background()
	reads := map[string]func(*Service) error{
		"city":     func(s *Service) error { _, err := s.GetCity(ctx, "99"); return err },
		"district": func(s *Service) error { _, err := s.GetDistrict(ctx, "9999"); return err },
		"village":  func(s *Service) error { _, err := s.GetVillage(ctx, "999999"); return err },
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			repo := fallbackRepo()
			up := fallbackUpstream(t)
			err := read(newTestService(t, repo, up))
			if !errors.Is(err, domainlocation.ErrNotFound) {
				t.Fatalf("read = %v, want ErrNotFound", err)
			}
			if up.calls() != 0 || repo.upsertCityCount+repo.upsertDistrictCount+repo.upsertVillageCount != 0 {
				t.Fatalf("an unknown parent reached the upstream (%d calls) or the tables", up.calls())
			}
		})
	}
}

func TestAVillageWhoseCityIsMissingIsNotFound(t *testing.T) {
	repo := fallbackRepo()
	repo.knownCities = nil
	up := fallbackUpstream(t)
	if _, err := newTestService(t, repo, up).GetVillage(context.Background(), "167101"); !errors.Is(err, domainlocation.ErrNotFound) || up.calls() != 0 {
		t.Fatalf("err = %v, upstream calls = %d", err, up.calls())
	}
}

func TestInvalidCodesNeverReachTheRepositoryTheCacheOrTheUpstream(t *testing.T) {
	bad := []string{"", "3*", "31?", "[0-9]", "31 ", "31%", strings.Repeat("1", 21), "abc", "../etc"}
	for _, code := range bad {
		repo := fallbackRepo()
		up := fallbackUpstream(t)
		cache := newFakeCache()
		svc := NewService(repo, Options{Cache: cache, HeartbeatInterval: time.Hour})
		svc.httpClient = &http.Client{Transport: up}
		for name, read := range map[string]func() error{
			"city":     func() error { _, err := svc.GetCity(context.Background(), code); return err },
			"district": func() error { _, err := svc.GetDistrict(context.Background(), code); return err },
			"village":  func() error { _, err := svc.GetVillage(context.Background(), code); return err },
		} {
			if err := read(); !errors.Is(err, domainlocation.ErrInvalidCode) {
				t.Fatalf("%s(%q) = %v, want ErrInvalidCode", name, code, err)
			}
		}
		if up.calls() != 0 || repo.lookups != 0 || len(cache.gets) != 0 {
			t.Fatalf("code %q reached the upstream (%d), the repository (%d) or the cache (%d)", code, up.calls(), repo.lookups, len(cache.gets))
		}
		_ = svc.Close(context.Background())
	}
}

func TestOnlyItemsOfTheRequestedParentAreStored(t *testing.T) {
	repo := fallbackRepo()
	up := answering(`[{"code":"71","name":"Kota Palembang"},{"code":"1101","name":"Banda Aceh"},{"code":"3171","name":"Jakarta Selatan"},{"code":"1672","name":"Kota Lubuklinggau"}]`)
	got, err := newTestService(t, repo, up).GetCity(context.Background(), "16")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v, %v, want the two cities of province 16", got, err)
	}
	for _, c := range repo.upsertedCities {
		if !strings.HasPrefix(c.Code, "16") || c.ProvinceCode != "16" {
			t.Fatalf("a city of another province was stored: %+v", c)
		}
	}
}

func TestAnUpstreamFailureIsReportedAndRememberedBriefly(t *testing.T) {
	repo := fallbackRepo()
	failing := true
	up := &upstream{handle: func(*http.Request) *http.Response {
		if failing {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: http.NoBody, Header: make(http.Header)}
		}
		return okResponse(`[{"code":"71","name":"Kota Palembang"}]`)
	}}
	svc := NewService(repo, Options{FailureTTL: 40 * time.Millisecond, HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: up}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	for i := range 4 {
		if _, err := svc.GetCity(context.Background(), "16"); !errors.Is(err, domainlocation.ErrUpstream) {
			t.Fatalf("read %d = %v, want ErrUpstream", i, err)
		}
	}
	if up.calls() != 1 {
		t.Fatalf("upstream called %d times for 4 reads during an outage, want 1", up.calls())
	}

	failing = false
	time.Sleep(60 * time.Millisecond)
	if got, err := svc.GetCity(context.Background(), "16"); err != nil || len(got) != 1 {
		t.Fatalf("after the memory expired: %+v, %v", got, err)
	}
}

func TestAnEmptyUpstreamAnswerIsRemembered(t *testing.T) {
	repo := fallbackRepo()
	up := answering(`[]`)
	svc := NewService(repo, Options{MissTTL: time.Hour, HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: up}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	for i := range 5 {
		got, err := svc.GetCity(context.Background(), "16")
		if err != nil || len(got) != 0 {
			t.Fatalf("read %d = %+v, %v, want an empty list", i, got, err)
		}
	}
	if up.calls() != 1 {
		t.Fatalf("upstream called %d times for 5 reads of an empty level, want 1", up.calls())
	}

	if _, err := svc.GetDistrict(context.Background(), "1671"); err != nil || up.calls() != 2 {
		t.Fatalf("a different level must ask again: err=%v calls=%d", err, up.calls())
	}
}

func TestARememberedEmptyAnswerExpires(t *testing.T) {
	repo := fallbackRepo()
	up := answering(`[]`)
	svc := NewService(repo, Options{MissTTL: 30 * time.Millisecond, HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: up}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	_, _ = svc.GetCity(context.Background(), "16")
	time.Sleep(60 * time.Millisecond)
	_, _ = svc.GetCity(context.Background(), "16")
	if up.calls() != 2 {
		t.Fatalf("upstream called %d times, want a second call after the TTL", up.calls())
	}
}

func TestConcurrentReadsOfAnEmptyLevelShareOneUpstreamCall(t *testing.T) {
	repo := fallbackRepo()
	release := make(chan struct{})
	up := &upstream{handle: func(*http.Request) *http.Response {
		<-release
		return okResponse(`[{"code":"71","name":"Kota Palembang"}]`)
	}}
	svc := newTestService(t, repo, up)

	const readers = 8
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			if got, err := svc.GetCity(context.Background(), "16"); err != nil || len(got) != 1 {
				t.Errorf("GetCity = %+v, %v", got, err)
			}
		})
	}
	deadline := time.After(5 * time.Second)
	for up.calls() == 0 {
		select {
		case <-deadline:
			t.Fatal("no request reached the upstream")
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if up.calls() != 1 {
		t.Fatalf("upstream called %d times for %d concurrent reads, want 1", up.calls(), readers)
	}
}

func TestACanceledRequestDoesNotFailTheSharedCall(t *testing.T) {
	repo := fallbackRepo()
	release := make(chan struct{})
	up := &upstream{handle: func(*http.Request) *http.Response {
		<-release
		return okResponse(`[{"code":"71","name":"Kota Palembang"}]`)
	}}
	svc := newTestService(t, repo, up)

	first, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { _, err := svc.GetCity(first, "16"); firstDone <- err }()
	for up.calls() == 0 {
		time.Sleep(time.Millisecond)
	}
	secondDone := make(chan error, 1)
	go func() { _, err := svc.GetCity(context.Background(), "16"); secondDone <- err }()
	time.Sleep(100 * time.Millisecond)

	cancelFirst()
	close(release)
	if err := <-secondDone; err != nil {
		t.Fatalf("the second reader failed because the first request was canceled: %v", err)
	}
	<-firstDone
}

func TestReadsAreServedFromTheCacheWithoutTheRepository(t *testing.T) {
	cache := newFakeCache()
	cache.data["location:city:16"] = locationsOf("1671", "Palembang")
	repo := &locationRepoTestDouble{listErr: errors.New("must not be called")}
	svc := NewService(repo, Options{Cache: cache, HeartbeatInterval: time.Hour})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	if got, err := svc.GetCity(context.Background(), "16"); err != nil || len(got) != 1 {
		t.Fatalf("GetCity = %+v, %v", got, err)
	}
}
