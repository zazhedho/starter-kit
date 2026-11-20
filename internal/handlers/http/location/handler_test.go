package location

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

type locationServiceTestDouble struct {
	locations []dtolocation.Location
	job       dtolocation.SyncJob
	err       error
	startReq  dtolocation.SyncRequest
	requested string
	lookups   int // GetSyncJob calls
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
func (m *locationServiceTestDouble) StartSync(ctx context.Context, req dtolocation.SyncRequest, requestedBy string) (dtolocation.SyncJob, error) {
	m.startReq = req
	m.requested = requestedBy
	return m.job, m.err
}
func (m *locationServiceTestDouble) GetSyncJob(ctx context.Context, id string) (dtolocation.SyncJob, error) {
	m.lookups++
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

// Every read maps the service's errors through the one mapper.
func TestLocationReadsMapDomainErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{domainlocation.NewInvalidCode("province_code"), http.StatusBadRequest},
		{fmt.Errorf("wrapped: %w", domainlocation.ErrNotFound), http.StatusNotFound},
		{fmt.Errorf("%w: boom", domainlocation.ErrUpstream), http.StatusBadGateway},
		{errors.New("database down"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		for name, target := range map[string]string{
			"city": "/city?province_code=11", "district": "/district?city_code=1101", "village": "/village?district_code=110101",
		} {
			handler := New(&locationServiceTestDouble{err: c.err})
			call := map[string]gin.HandlerFunc{"city": handler.GetCity, "district": handler.GetDistrict, "village": handler.GetVillage}[name]
			rec := performLocationRequest(http.MethodGet, "/"+name, target, nil, call, nil)
			if rec.Code != c.status {
				t.Fatalf("%s with %v = %d, want %d: %s", name, c.err, rec.Code, c.status, rec.Body.String())
			}
		}
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

const jobID = "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a10"

func TestLocationGetSyncJobMapsNotFound(t *testing.T) {
	handler := New(&locationServiceTestDouble{err: domainlocation.ErrSyncJobNotFound})
	rec := performLocationRequest(http.MethodGet, "/sync/:id", "/sync/"+jobID, nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&locationServiceTestDouble{job: dtolocation.SyncJob{ID: "job-1", Status: "done"}})
	rec = performLocationRequest(http.MethodGet, "/sync/:id", "/sync/"+jobID, nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&locationServiceTestDouble{err: errors.New("database down")})
	rec = performLocationRequest(http.MethodGet, "/sync/:id", "/sync/"+jobID, nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = performLocationRequest(http.MethodGet, "/sync", "/sync", nil, handler.GetSyncJob, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing id 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A job id that is not a UUID is a malformed request, not a lookup that fails.
func TestLocationGetSyncJobRejectsAnIdThatIsNotAUUID(t *testing.T) {
	service := &locationServiceTestDouble{err: errors.New("must not be called")}
	handler := New(service)
	for _, id := range []string{"job-1", "123", "2d5ea3a8", "x'OR'1'='1"} {
		rec := performLocationRequest(http.MethodGet, "/sync/:id", "/sync/"+id, nil, handler.GetSyncJob, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("id %q: status = %d, want 400: %s", id, rec.Code, rec.Body.String())
		}
	}
	if service.lookups != 0 {
		t.Fatal("the service was called with a malformed id")
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

// A client error is expected traffic: it is logged at WARN, never at ERROR.
func TestClientErrorsAreLoggedAtWarnAndServerErrorsAtError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantLevel string
	}{
		{"validation", domainlocation.NewInvalidSync("province_code is required for city sync"), "WARN"},
		{"invalid code", domainlocation.NewInvalidCode("province_code"), "WARN"},
		{"unknown parent", domainlocation.ErrNotFound, "WARN"},
		{"upstream", domainlocation.ErrUpstream, "ERROR"},
		{"unexpected", errors.New("database down"), "ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := New(&locationServiceTestDouble{err: c.err})
			mark := logs.Mark()
			performLocationRequest(http.MethodGet, "/city", "/city?province_code=31", nil, handler.GetCity, nil)

			out := logs.Since(mark)
			if !strings.Contains(out, `"level":"`+c.wantLevel+`"`) {
				t.Fatalf("want a %s log line, got:\n%s", c.wantLevel, out)
			}
			if c.wantLevel == "WARN" && strings.Contains(out, `"level":"ERROR"`) {
				t.Fatalf("a client error was logged at ERROR:\n%s", out)
			}
		})
	}
}

// envelope is the wire shape every handler answers with: error is always a
// list of {field, code, message}, and message is the handler's fixed text.
type envelope struct {
	LogID   uuid.UUID       `json:"log_id"`
	Code    int             `json:"code"`
	Status  bool            `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Error   []struct {
		Field   string `json:"field"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var res envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("not an envelope: %v: %s", err, rec.Body.String())
	}
	if res.LogID == uuid.Nil || res.Code != rec.Code {
		t.Fatalf("log_id %v code %d, want a log id and code %d: %s", res.LogID, res.Code, rec.Code, rec.Body.String())
	}
	return res
}

func TestLocationErrorsUseTheErrorListEnvelope(t *testing.T) {
	cases := []struct {
		name        string
		service     *locationServiceTestDouble
		method      string
		route, path string
		call        func(*Handler) gin.HandlerFunc
		body        any
		status      int
		message     string
		detail      string
		wantData    bool
	}{
		{"missing parent code", &locationServiceTestDouble{}, http.MethodGet, "/city", "/city",
			func(h *Handler) gin.HandlerFunc { return h.GetCity }, nil,
			http.StatusBadRequest, gokit.MsgInvalidRequest, "province_code is required", false},
		{"sync already running", &locationServiceTestDouble{err: domainlocation.ErrSyncRunning, job: dtolocation.SyncJob{ID: "job-1"}}, http.MethodPost, "/sync", "/sync",
			func(h *Handler) gin.HandlerFunc { return h.Sync }, dtolocation.SyncRequest{Level: "province"},
			http.StatusConflict, msgSyncRunning, msgSyncRunning, true},
		{"invalid sync", &locationServiceTestDouble{err: domainlocation.NewInvalidSync("invalid sync level")}, http.MethodPost, "/sync", "/sync",
			func(h *Handler) gin.HandlerFunc { return h.Sync }, dtolocation.SyncRequest{Level: "province"},
			http.StatusBadRequest, gokit.MsgInvalidRequest, "invalid sync level", false},
		{"unknown job", &locationServiceTestDouble{err: domainlocation.ErrSyncJobNotFound}, http.MethodGet, "/sync/:id", "/sync/" + jobID,
			func(h *Handler) gin.HandlerFunc { return h.GetSyncJob }, nil,
			http.StatusNotFound, gokit.MsgResourceNotFound, "location sync job not found", false},
		{"unknown parent", &locationServiceTestDouble{err: domainlocation.ErrNotFound}, http.MethodGet, "/district", "/district?city_code=9999",
			func(h *Handler) gin.HandlerFunc { return h.GetDistrict }, nil,
			http.StatusNotFound, gokit.MsgResourceNotFound, "location not found", false},
		{"invalid code", &locationServiceTestDouble{err: domainlocation.NewInvalidCode("city_code")}, http.MethodGet, "/district", "/district?city_code=31*",
			func(h *Handler) gin.HandlerFunc { return h.GetDistrict }, nil,
			http.StatusBadRequest, gokit.MsgInvalidRequest, "city_code must be 1 to 20 digits", false},
		{"upstream down", &locationServiceTestDouble{err: fmt.Errorf("%w: status 500", domainlocation.ErrUpstream)}, http.MethodGet, "/city", "/city?province_code=31",
			func(h *Handler) gin.HandlerFunc { return h.GetCity }, nil,
			http.StatusBadGateway, "An upstream service failed to answer", "the location service is not available", false},
		{"shutting down", &locationServiceTestDouble{err: domainlocation.ErrShuttingDown}, http.MethodPost, "/sync", "/sync",
			func(h *Handler) gin.HandlerFunc { return h.Sync }, dtolocation.SyncRequest{Level: "province"},
			http.StatusServiceUnavailable, "The service is unavailable", "the service is shutting down", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := performLocationRequest(c.method, c.route, c.path, c.body, c.call(New(c.service)), nil)
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			requireErrorEnvelope(t, rec, c.message, c.detail, c.wantData)
		})
	}
}

// requireErrorEnvelope checks a failed response: false status, one error entry
// with a code, and data present only when wantData.
func requireErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, message, detail string, wantData bool) {
	t.Helper()
	res := decodeEnvelope(t, rec)
	if res.Status || res.Message != message {
		t.Fatalf("status %v message %q, want false and %q", res.Status, res.Message, message)
	}
	if len(res.Error) != 1 || res.Error[0].Message != detail || res.Error[0].Code == "" {
		t.Fatalf("error = %+v, want one entry %q with a code", res.Error, detail)
	}
	if carriesData(res.Data) != wantData {
		t.Fatalf("data = %s, want present=%v", res.Data, wantData)
	}
}

func carriesData(data json.RawMessage) bool {
	return len(data) > 0 && string(data) != "null"
}

// A nil result list is sent as [], never null.
func TestLocationEmptyListIsAnEmptyArray(t *testing.T) {
	handler := New(&locationServiceTestDouble{})
	rec := performLocationRequest(http.MethodGet, "/province", "/province", nil, handler.GetProvince, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if res := decodeEnvelope(t, rec); !res.Status || strings.TrimSpace(string(res.Data)) != "[]" || len(res.Error) != 0 {
		t.Fatalf("got %s, want status true, data [] and no error", rec.Body.String())
	}
}
