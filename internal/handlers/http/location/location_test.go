package location

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
	"testing"

	"github.com/gin-gonic/gin"
)

type locationServiceTestDouble struct {
	locations []dtolocation.Location
	job       dtolocation.SyncJob
	err       error
	startReq  dtolocation.SyncRequest
	requested string
}

func (m *locationServiceTestDouble) GetProvince(ctx context.Context) ([]dtolocation.Location, error) {
	return m.locations, m.err
}
func (m *locationServiceTestDouble) GetCity(ctx context.Context, provinceCode string) ([]dtolocation.Location, error) {
	return m.locations, m.err
}
func (m *locationServiceTestDouble) GetDistrict(ctx context.Context, cityCode string) ([]dtolocation.Location, error) {
	return m.locations, m.err
}
func (m *locationServiceTestDouble) GetVillage(ctx context.Context, districtCode string) ([]dtolocation.Location, error) {
	return m.locations, m.err
}
func (m *locationServiceTestDouble) StartSync(ctx context.Context, req dtolocation.SyncRequest) (dtolocation.SyncJob, error) {
	m.startReq = req
	m.requested = authkit.ScopeFrom(ctx).ActorUserID()
	return m.job, m.err
}
func (m *locationServiceTestDouble) GetSyncJob(ctx context.Context, id string) (dtolocation.SyncJob, error) {
	return m.job, m.err
}

func performLocationRequest(method, routePath, requestPath string, body any, handler gin.HandlerFunc, authData map[string]any) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, routePath, func(ctx *gin.Context) {
		if authData != nil {
			userID, _ := authData["user_id"].(string)
			role, _ := authData["role"].(string)
			ctx.Request = ctx.Request.WithContext(authkit.WithScope(ctx.Request.Context(), authkit.NewScope(userID, "", role, nil)))
		}
		handler(ctx)
	})
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, requestPath, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestLocationListHandlersValidateRequiredQueries(t *testing.T) {
	handler := New(&locationServiceTestDouble{locations: []dtolocation.Location{{Code: "11", Name: "Aceh"}}})

	if rec := performLocationRequest(http.MethodGet, "/province", "/province", nil, handler.GetProvince, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected province 200, got %d", rec.Code)
	}
	if rec := performLocationRequest(http.MethodGet, "/city", "/city", nil, handler.GetCity, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected city 400, got %d", rec.Code)
	}
	if rec := performLocationRequest(http.MethodGet, "/district", "/district", nil, handler.GetDistrict, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected district 400, got %d", rec.Code)
	}
	if rec := performLocationRequest(http.MethodGet, "/village", "/village", nil, handler.GetVillage, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected village 400, got %d", rec.Code)
	}

	if rec := performLocationRequest(http.MethodGet, "/city", "/city?province_code=11", nil, handler.GetCity, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected city 200, got %d", rec.Code)
	}
	if rec := performLocationRequest(http.MethodGet, "/district", "/district?city_code=1101", nil, handler.GetDistrict, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected district 200, got %d", rec.Code)
	}
	if rec := performLocationRequest(http.MethodGet, "/village", "/village?district_code=110101", nil, handler.GetVillage, nil); rec.Code != http.StatusOK {
		t.Fatalf("expected village 200, got %d", rec.Code)
	}
}

func TestLocationListHandlersMapServiceErrors(t *testing.T) {
	handler := New(&locationServiceTestDouble{err: errors.New("database down")})

	tests := []struct {
		name      string
		routePath string
		path      string
		call      gin.HandlerFunc
	}{
		{name: "province", routePath: "/province", path: "/province", call: handler.GetProvince},
		{name: "city", routePath: "/city", path: "/city?province_code=11", call: handler.GetCity},
		{name: "district", routePath: "/district", path: "/district?city_code=1101", call: handler.GetDistrict},
		{name: "village", routePath: "/village", path: "/village?district_code=110101", call: handler.GetVillage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performLocationRequest(http.MethodGet, tt.routePath, tt.path, nil, tt.call, nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLocationSyncMapsAcceptedConflictAndBadRequest(t *testing.T) {
	service := &locationServiceTestDouble{job: dtolocation.SyncJob{ID: "job-1", Status: "queued"}}
	handler := New(service)
	rec := performLocationRequest(http.MethodPost, "/sync", "/sync", dtolocation.SyncRequest{Level: "province"}, handler.Sync, map[string]any{
		"user_id": "user-1",
		"role":    "admin",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if service.requested != "user-1" {
		t.Fatalf("expected actor user id, got %q", service.requested)
	}

	handler = New(&locationServiceTestDouble{err: domainlocation.ErrSyncRunning, job: dtolocation.SyncJob{ID: "job-1"}})
	rec = performLocationRequest(http.MethodPost, "/sync", "/sync", dtolocation.SyncRequest{Level: "province"}, handler.Sync, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}

	handler = New(&locationServiceTestDouble{err: domainlocation.NewInvalidSync("invalid sync level")})
	rec = performLocationRequest(http.MethodPost, "/sync", "/sync", dtolocation.SyncRequest{Level: "province"}, handler.Sync, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	rec = performLocationRequest(http.MethodPost, "/sync", "/sync", map[string]any{"level": 123}, handler.Sync, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid json 400, got %d", rec.Code)
	}
}

func TestLocationGetSyncJobMapsNotFound(t *testing.T) {
	handler := New(&locationServiceTestDouble{err: domainlocation.ErrNotFound})
	rec := performLocationRequest(http.MethodGet, "/sync/:id", "/sync/job-1", nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&locationServiceTestDouble{job: dtolocation.SyncJob{ID: "job-1", Status: "done"}})
	rec = performLocationRequest(http.MethodGet, "/sync/:id", "/sync/job-1", nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&locationServiceTestDouble{err: errors.New("database down")})
	rec = performLocationRequest(http.MethodGet, "/sync/:id", "/sync/job-1", nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = performLocationRequest(http.MethodGet, "/sync", "/sync", nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing id 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLocationSyncMapsStartErrors(t *testing.T) {
	req := dtolocation.SyncRequest{Level: "province"}
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"already running", domainlocation.ErrSyncRunning, http.StatusConflict},
		{"validation", domainlocation.NewInvalidSync("province_code is required for city sync"), http.StatusBadRequest},
		{"wrapped validation", fmt.Errorf("start: %w", domainlocation.NewInvalidSync("invalid sync level")), http.StatusBadRequest},
		{"unexpected", errors.New("pq: connection refused"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := New(&locationServiceTestDouble{err: c.err})
			rec := performLocationRequest(http.MethodPost, "/sync", "/sync", req, handler.Sync, nil)
			if rec.Code != c.wantStatus {
				t.Fatalf("expected %d, got %d: %s", c.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLocationSyncUnexpectedErrorUsesGenericResponse(t *testing.T) {
	handler := New(&locationServiceTestDouble{err: errors.New("pq: connection refused")})
	rec := performLocationRequest(http.MethodPost, "/sync", "/sync", dtolocation.SyncRequest{Level: "province"}, handler.Sync, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pq:") {
		t.Fatalf("internal error text leaked: %s", rec.Body.String())
	}
	var got struct {
		LogID uuid.UUID `json:"log_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.LogID == uuid.Nil {
		t.Fatalf("expected a log id in the response (err=%v): %s", err, rec.Body.String())
	}
	want, err := json.Marshal(gokit.InternalServerError(got.LogID))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, rec.Body.Bytes(), want) {
		t.Fatalf("expected the generic internal-error response\n got: %s\nwant: %s", rec.Body.String(), want)
	}
}

func TestLocationSyncValidationEchoesMessage(t *testing.T) {
	handler := New(&locationServiceTestDouble{err: domainlocation.NewInvalidSync("province_code is required for city sync")})
	rec := performLocationRequest(http.MethodPost, "/sync", "/sync", dtolocation.SyncRequest{Level: "city"}, handler.Sync, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "province_code is required for city sync") {
		t.Fatalf("expected 400 with the validation message, got %d: %s", rec.Code, rec.Body.String())
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}
