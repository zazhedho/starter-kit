package location

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	domainlocation "starter-kit/internal/domain/location"
)

func TestFetchEntriesReadsBothResponseShapesTheSameWay(t *testing.T) {
	// The same three provinces, in the shapes the Location Service has used:
	// each with a blank-padded name, one with a code that is not a code.
	bodies := map[string]string{
		"array":         `[{"code":"32","name":" Jawa Barat "},{"code":"31","name":"DKI Jakarta"},{"code":"3x","name":"Broken"},{"code":"11","name":"Aceh"}]`,
		"wrapped array": `{"log_id":"t","data":[{"code":"32","name":" Jawa Barat "},{"code":"31","name":"DKI Jakarta"},{"code":"3x","name":"Broken"},{"code":"11","name":"Aceh"}]}`,
		"map":           `{"32":" Jawa Barat ","31":"DKI Jakarta","3x":"Broken","11":"Aceh"}`,
		"wrapped map":   `{"data":{"32":" Jawa Barat ","31":"DKI Jakarta","3x":"Broken","11":"Aceh"}}`,
	}
	want := []entry{{"11", "Aceh"}, {"31", "DKI Jakarta"}, {"32", "Jawa Barat"}}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			svc := newTestService(t, &locationRepoTestDouble{}, answering(body))
			got, err := svc.fetchEntries(context.Background(), "province", "/api/locations/provinces", nil, "")
			if err != nil {
				t.Fatalf("fetchEntries = %v", err)
			}
			if len(got) != len(want) {
				t.Fatalf("entries = %+v, want %+v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("entries = %+v, want %+v (sorted by name, trimmed, invalid code dropped)", got, want)
				}
			}
		})
	}
}

func TestFetchEntriesDropsWhatDoesNotBelongOrIsNotValid(t *testing.T) {
	longName := strings.Repeat("n", 256)
	body := `[
		{"code":"71","name":"Jakarta Selatan"},
		{"code":"3172","name":"Jakarta Utara"},
		{"code":"1101","name":"Foreign full code"},
		{"code":"7","name":""},
		{"code":"8","name":"` + longName + `"},
		{"code":"9;DROP","name":"Injected"},
		{"code":"71","name":"Duplicate wins last"}
	]`
	svc := newTestService(t, &locationRepoTestDouble{}, answering(body))
	got, err := svc.fetchEntries(context.Background(), "city", "/api/locations/regencies", nil, "31")
	if err != nil {
		t.Fatal(err)
	}
	want := []entry{{"3171", "Duplicate wins last"}, {"3172", "Jakarta Utara"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
}

func TestFetchEntriesAcceptsAName255CharactersLong(t *testing.T) {
	name := strings.Repeat("é", 255) // 255 characters, 510 bytes
	svc := newTestService(t, &locationRepoTestDouble{}, answering(`{"31":"`+name+`"}`))
	got, err := svc.fetchEntries(context.Background(), "province", "/p", nil, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v: the limit counts characters, as the column does", got, err)
	}
}

func TestEveryUpstreamFailureIsAnErrUpstream(t *testing.T) {
	cases := map[string]http.RoundTripper{
		"status": roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}),
		"transport": roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network down") }),
		"decode":    answering(`{`),
		"shape":     answering(`"just a string"`),
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			svc := newTestService(t, &locationRepoTestDouble{}, rt)
			_, err := svc.fetchEntries(context.Background(), "province", "/api/locations/provinces", nil, "")
			if !errors.Is(err, domainlocation.ErrUpstream) {
				t.Fatalf("fetchEntries = %v, want ErrUpstream", err)
			}
		})
	}
}

func TestFetchEntriesReadsNoMoreThanTheConfiguredCap(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// An endless body: a reader without a cap would never return.
		chunk := []byte(strings.Repeat("x", 4096))
		for {
			n, err := w.Write(chunk)
			served.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	svc := NewService(&locationRepoTestDouble{}, Options{BaseURL: srv.URL, MaxResponseBytes: 10 << 10})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	_, err := svc.fetchEntries(context.Background(), "province", "/api/locations/provinces", nil, "")
	if !errors.Is(err, domainlocation.ErrUpstream) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("fetchEntries = %v, want an oversize ErrUpstream", err)
	}
}

func TestAResponseExactlyAtTheCapIsAccepted(t *testing.T) {
	body := `{"31":"DKI Jakarta"}`
	svc := NewService(&locationRepoTestDouble{}, Options{MaxResponseBytes: int64(len(body))})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	svc.httpClient = &http.Client{Transport: answering(body)}
	if got, err := svc.fetchEntries(context.Background(), "province", "/p", nil, ""); err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		_, _ = io.WriteString(w, `{"31":"DKI Jakarta"}`)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()

	svc := NewService(&locationRepoTestDouble{}, Options{BaseURL: srv.URL})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	_, err := svc.fetchEntries(context.Background(), "province", "/api/locations/provinces", nil, "")
	if !errors.Is(err, domainlocation.ErrUpstream) {
		t.Fatalf("fetchEntries = %v, want ErrUpstream for a redirect", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the redirect target was requested")
	}
}

func TestDecodePairsStopsUnwrappingDeepEnvelopes(t *testing.T) {
	deep := `{"data":{"data":{"data":{"data":{"31":"DKI Jakarta"}}}}}`
	if got, err := decodePairs([]byte(deep), 0); err == nil && len(got) == 1 && got[0].Code == "31" {
		t.Fatalf("an envelope nested more than %d deep must not be unwrapped to data", maxEnvelopeDepth)
	}
}

func TestLocationServiceURLEncodesAndSkipsBlankQueryValues(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, nil)
	svc.baseURL = "https://locations.example.invalid/"
	got := svc.locationServiceURL("/api/locations/regencies", map[string]string{"province_code": "31", "code_format": "short", "blank": " "})
	want := "https://locations.example.invalid/api/locations/regencies?code_format=short&province_code=31"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func newScopedSync(t *testing.T, repo *locationRepoTestDouble) *Service {
	t.Helper()
	return newTestService(t, repo, scopedUpstream())
}

// scopedUpstream serves one province, with one city, district and village under it.
func scopedUpstream() *upstream {
	return &upstream{handle: func(req *http.Request) *http.Response {
		body := `{}`
		switch {
		case strings.Contains(req.URL.Path, "/api/locations/provinces"):
			body = `{"data":[{"code":"31","full_code":"31","name":"DKI Jakarta","level":"province"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/regencies"):
			body = `{"data":[{"code":"71","full_code":"31.71","name":"Jakarta Selatan","level":"regency","parent_code":"31"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/districts"):
			body = `{"data":[{"code":"01","full_code":"31.71.01","name":"Tebet","level":"district","parent_code":"31.71"}]}`
		case strings.Contains(req.URL.Path, "/api/locations/villages"):
			body = `{"data":[{"code":"01","full_code":"31.71.01.0001","name":"Tebet Barat","level":"village","parent_code":"31.71.01"}]}`
		}
		return okResponse(body)
	}}
}

// relativeCodesUpstream answers each level and fails the test unless the
// request carries the relative codes of its parents.
func relativeCodesUpstream(t *testing.T) *upstream {
	return &upstream{handle: func(req *http.Request) *http.Response {
		q := req.URL.Query()
		requireQuery(t, req.URL.Path, q, map[string]string{"code_format": "short"})
		switch {
		case strings.Contains(req.URL.Path, "regencies"):
			requireQuery(t, "regencies", q, map[string]string{"province_code": "31"})
			return okResponse(`[{"code":"71","name":"Jakarta Selatan"}]`)
		case strings.Contains(req.URL.Path, "districts"):
			requireQuery(t, "districts", q, map[string]string{"province_code": "31", "regency_code": "71"})
			return okResponse(`[{"code":"01","name":"Tebet"}]`)
		default:
			requireQuery(t, "villages", q, map[string]string{"regency_code": "71", "district_code": "01"})
			return okResponse(`[{"code":"0001","name":"Tebet Barat"}]`)
		}
	}}
}

func requireQuery(t *testing.T, label string, q url.Values, want map[string]string) {
	t.Helper()
	for key, value := range want {
		if got := q.Get(key); got != value {
			t.Errorf("%s: %s = %q, want %q", label, key, got, value)
		}
	}
}

func TestFetchLevelsSendTheRelativeCodesAndStoreFullOnes(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, relativeCodesUpstream(t))
	ctx := context.Background()

	cities, err := svc.fetchCities(ctx, "31")
	if err != nil || len(cities) != 1 || cities[0].Code != "3171" || cities[0].ProvinceCode != "31" {
		t.Fatalf("cities = %+v, %v", cities, err)
	}
	districts, err := svc.fetchDistricts(ctx, "31", "3171")
	if err != nil || len(districts) != 1 || districts[0].Code != "317101" || districts[0].CityCode != "3171" {
		t.Fatalf("districts = %+v, %v", districts, err)
	}
	villages, err := svc.fetchVillages(ctx, "31", "3171", "317101")
	if err != nil || len(villages) != 1 || villages[0].Code != "3171010001" || villages[0].DistrictCode != "317101" {
		t.Fatalf("villages = %+v, %v", villages, err)
	}
}
