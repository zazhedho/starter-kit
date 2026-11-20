package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

func TestMediaErrorResponseMapsDomainErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		msg    string
	}{
		{"not found", domainmedia.ErrNotFound, http.StatusNotFound, "media not found"},
		{"wrapped not found", fmt.Errorf("lookup: %w", domainmedia.ErrNotFound), http.StatusNotFound, "media not found"},
		{"forbidden hides existence", domainmedia.ErrMediaForbidden, http.StatusNotFound, "media not found"},
		{"empty file", domainmedia.ErrEmptyFile, http.StatusBadRequest, domainmedia.ErrEmptyFile.Error()},
		{"too large", domainmedia.ErrFileTooLarge, http.StatusRequestEntityTooLarge, domainmedia.ErrFileTooLarge.Error()},
		{"unexpected", errors.New("database down"), http.StatusInternalServerError, gokit.MsgSomethingWrong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, msg := mediaErrorResponse(c.err)
			if status != c.status || msg != c.msg {
				t.Fatalf("got (%d, %q), want (%d, %q)", status, msg, c.status, c.msg)
			}
		})
	}
}

type serviceDouble struct {
	maxFileSize int64
	media       domainmedia.Media
	err         error

	uploadOwner string
	uploadName  string
	deleteActor domainmedia.Actor
	deleteID    string
	calls       int

	listActor domainmedia.Actor
	listReq   dtomedia.ListRequest
	listItems []domainmedia.Media
	listTotal int64
	listLimit int
}

func (d *serviceDouble) List(_ context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) (dtomedia.ListResult, error) {
	d.calls++
	d.listActor, d.listReq = actor, req
	return dtomedia.ListResult{Items: d.listItems, Total: d.listTotal, Limit: d.listLimit}, d.err
}

func (d *serviceDouble) MaxFileSize() int64 { return d.maxFileSize }

func (d *serviceDouble) Upload(_ context.Context, owner string, _ multipart.File, header *multipart.FileHeader) (domainmedia.Media, error) {
	d.calls++
	d.uploadOwner, d.uploadName = owner, header.Filename
	return d.media, d.err
}

func (d *serviceDouble) Delete(_ context.Context, actor domainmedia.Actor, id string) (domainmedia.Media, error) {
	d.calls++
	d.deleteActor, d.deleteID = actor, id
	return d.media, d.err
}

func serve(t *testing.T, svc Service, userID, role string, req request) *httptest.ResponseRecorder {
	t.Helper()
	return serveWithPermissions(t, svc, caller{userID, role, nil}, req)
}

type caller struct {
	userID, role string
	permissions  []string
}

type request struct {
	method, target string
	body           []byte
	contentType    string
}

func serveWithPermissions(t *testing.T, svc Service, who caller, req request) *httptest.ResponseRecorder {
	t.Helper()
	return serveHandler(t, New(svc, nil, 0, 0, 0), who, req)
}

func serveHandler(t *testing.T, h *Handler, who caller, r request) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		scope := authkit.NewScope(who.userID, "tester", who.role, who.permissions)
		c.Request = c.Request.WithContext(authkit.WithScope(c.Request.Context(), scope))
	})
	engine.GET("/media", h.List)
	engine.POST("/media", h.Upload)
	engine.DELETE("/media/:id", h.Delete)

	req := httptest.NewRequest(r.method, r.target, bytes.NewReader(r.body))
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func multipartBody(t *testing.T, field, filename string, content []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if field != "" {
		part, err := w.CreateFormFile(field, filename)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write(content)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var res struct {
		Error []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not JSON with an error list: %v: %s", err, rec.Body.String())
	}
	if len(res.Error) != 1 || res.Error[0].Code == "" {
		t.Fatalf("error = %+v, want one entry with a code: %s", res.Error, rec.Body.String())
	}
	return res.Error[0].Message
}

func envelopeMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var res struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rec.Body.String())
	}
	return res.Message
}

func TestUploadHandlerPassesTheAuthenticatedUserToTheService(t *testing.T) {
	owner := uuid.NewString()
	svc := &serviceDouble{maxFileSize: 1024, media: domainmedia.Media{ID: "media-1", OwnerUserID: owner}}
	body, ct := multipartBody(t, "file", "a.png", []byte("data"))

	rec := serve(t, svc, owner, "viewer", request{http.MethodPost, "/media", body, ct})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.uploadOwner != owner || svc.uploadName != "a.png" {
		t.Fatalf("service got owner %q file %q", svc.uploadOwner, svc.uploadName)
	}
	if !strings.Contains(rec.Body.String(), "media-1") {
		t.Fatalf("response lacks the stored media: %s", rec.Body.String())
	}
}

func TestUploadHandlerRejectsARequestWithoutFile(t *testing.T) {
	svc := &serviceDouble{maxFileSize: 1024}
	body, ct := multipartBody(t, "", "", nil)

	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodPost, "/media", body, ct})

	if rec.Code != http.StatusBadRequest || errorMessage(t, rec) != "file is required" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 0 {
		t.Fatal("the service must not be called without a file")
	}
}

func TestUploadHandlerAnswers413ForABodyOverTheLimit(t *testing.T) {
	svc := &serviceDouble{maxFileSize: 10}
	body, ct := multipartBody(t, "file", "big.png", bytes.Repeat([]byte("x"), int(multipartOverhead)+1024))

	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodPost, "/media", body, ct})

	if rec.Code != http.StatusRequestEntityTooLarge || errorMessage(t, rec) != domainmedia.ErrFileTooLarge.Error() {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 0 {
		t.Fatal("the service must not be called for an oversized body")
	}
}

func TestUploadHandlerMapsServiceErrors(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"unsupported type", domainmedia.ErrUnsupportedContentType, http.StatusBadRequest, domainmedia.ErrUnsupportedContentType.Error()},
		{"owner is not a user id", domainmedia.ErrMediaForbidden, http.StatusNotFound, "media not found"},
		{"storage down", errors.New("minio: connection refused"), http.StatusInternalServerError, gokit.MsgSomethingWrong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &serviceDouble{maxFileSize: 1024, err: c.err}
			body, ct := multipartBody(t, "file", "a.png", []byte("data"))
			rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodPost, "/media", body, ct})
			if c.status == http.StatusInternalServerError {
				if rec.Code != c.status || !strings.HasPrefix(errorMessage(t, rec), c.message) {
					t.Fatalf("got %d %s, want 500 starting with %q", rec.Code, rec.Body.String(), c.message)
				}
			} else if rec.Code != c.status || errorMessage(t, rec) != c.message {
				t.Fatalf("got %d %s, want %d %q", rec.Code, rec.Body.String(), c.status, c.message)
			}
			if strings.Contains(rec.Body.String(), "connection refused") {
				t.Fatal("the response must not reveal the internal error")
			}
		})
	}
}

func TestActorFromMapsScopePermissions(t *testing.T) {
	user := uuid.NewString()
	cases := []struct {
		name  string
		role  string
		perms []string
		want  domainmedia.Actor
	}{
		{"plain user", "viewer", nil, domainmedia.Actor{UserID: user}},
		{"list_any only", "viewer", []string{"media:list_any"}, domainmedia.Actor{UserID: user, CanListAny: true}},
		{"delete_any only", "viewer", []string{"media:delete_any"}, domainmedia.Actor{UserID: user, CanDeleteAny: true}},
		{"other resource", "viewer", []string{"locations:list_any"}, domainmedia.Actor{UserID: user}},
		{"superadmin passes every check", authkit.RoleSuperAdmin, nil, domainmedia.Actor{UserID: user, CanListAny: true, CanDeleteAny: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := authkit.WithScope(context.Background(), authkit.NewScope(user, "tester", c.role, c.perms))
			if got := actorFrom(ctx); got != c.want {
				t.Fatalf("actorFrom = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestDeleteHandlerBuildsTheActorFromTheScope(t *testing.T) {
	id := uuid.NewString()
	user := uuid.NewString()
	svc := &serviceDouble{media: domainmedia.Media{ID: id}}
	rec := serveWithPermissions(t, svc, caller{user, "viewer", []string{"media:delete_any"}}, request{method: http.MethodDelete, target: "/media/" + id})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.deleteID != id || svc.deleteActor != (domainmedia.Actor{UserID: user, CanDeleteAny: true}) {
		t.Fatalf("service got id %q actor %+v", svc.deleteID, svc.deleteActor)
	}
}

func TestDeleteHandlerRejectsAnInvalidID(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodDelete, "/media/not-a-uuid", nil, ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 0 {
		t.Fatal("the service must not be called for an invalid id")
	}
}

func TestDeleteHandlerMapsServiceErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"missing", domainmedia.ErrNotFound, http.StatusNotFound},
		{"someone else's", domainmedia.ErrMediaForbidden, http.StatusNotFound},
		{"unexpected", errors.New("database down"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &serviceDouble{err: c.err}
			id := uuid.NewString()
			rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodDelete, "/media/" + id, nil, ""})
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, c.status, rec.Body.String())
			}
		})
	}
}

func TestListHandlerRejectsABadPageNumber(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media?page=abc", nil, ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 0 {
		t.Fatal("the service must not be called for a bad query")
	}
}

func TestListHandlerRejectsABadOwnerFilter(t *testing.T) {
	for _, target := range []string{
		"/media?filters[owner_user_id]=not-a-uuid",
		`/media?filters[owner_user_id]=["x"]`,
		"/media?filters[owner_user_id]=42",
	} {
		t.Run(target, func(t *testing.T) {
			svc := &serviceDouble{}
			rec := serveWithPermissions(t, svc, caller{uuid.NewString(), "viewer", []string{"media:list_any"}}, request{method: http.MethodGet, target: target})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if svc.calls != 0 {
				t.Fatal("the service must not be called for a bad owner filter")
			}
		})
	}
}

func TestListHandlerAppliesDefaultsAndPassesQuery(t *testing.T) {
	user, other := uuid.NewString(), uuid.NewString()
	svc := &serviceDouble{}
	rec := serve(t, svc, user, "viewer", request{http.MethodGet, "/media", nil, ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	want := dtomedia.ListRequest{Page: 1, Limit: 20}
	if svc.listReq != want {
		t.Fatalf("defaults: got %+v, want %+v", svc.listReq, want)
	}
	if svc.listActor != (domainmedia.Actor{UserID: user}) {
		t.Fatalf("actor = %+v", svc.listActor)
	}

	target := "/media?search=cat&page=3&limit=5&order_by=size&order_direction=asc" +
		"&filters[owner_user_id]=" + other + "&filters[content_type]=image/png&filters[object_key]=secret"
	svc = &serviceDouble{}
	if rec := serve(t, svc, user, "viewer", request{http.MethodGet, target, nil, ""}); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	want = dtomedia.ListRequest{
		Search: "cat", OwnerUserID: other, ContentType: "image/png",
		OrderBy: "size", OrderDirection: "asc", Page: 3, Limit: 5,
	}
	if svc.listReq != want {
		t.Fatalf("got %+v, want %+v", svc.listReq, want)
	}
}

func TestListHandlerRespondsWithThePaginationShape(t *testing.T) {
	svc := &serviceDouble{listItems: []domainmedia.Media{{ID: "m-1", OwnerUserID: "u-1"}}, listTotal: 41, listLimit: 20}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media?limit=20&page=2", nil, ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		TotalData   int  `json:"total_data"`
		TotalPages  int  `json:"total_pages"`
		CurrentPage int  `json:"current_page"`
		NextPage    bool `json:"next_page"`
		PrevPage    bool `json:"prev_page"`
		Limit       int  `json:"limit"`
		Data        []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rec.Body.String())
	}
	if res.TotalData != 41 || res.TotalPages != 3 || res.CurrentPage != 2 || !res.NextPage || !res.PrevPage || res.Limit != 20 {
		t.Fatalf("unexpected pagination %+v", res)
	}
	if len(res.Data) != 1 || res.Data[0].ID != "m-1" {
		t.Fatalf("unexpected data %+v", res.Data)
	}
}

func TestListHandlerMapsServiceErrors(t *testing.T) {
	svc := &serviceDouble{err: errors.New("database down")}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media", nil, ""})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestListHandlerPassesTheLimitAndReportsTheAppliedOne(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		wantLimit int
	}{
		{"minus one is the unbounded sentinel, left for the repository to refuse", "limit=-1&page=3", -1},
		{"zero falls back", "limit=0", defaultListLimit},
		{"missing falls back", "page=2", defaultListLimit},
		{"above the cap is left for the repository", "limit=10000", 10000},
		{"normal value", "limit=5&page=3", 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &serviceDouble{listLimit: 77}
			rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media?" + c.query, nil, ""})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if svc.listReq.Limit != c.wantLimit {
				t.Fatalf("limit passed to the service = %d, want %d", svc.listReq.Limit, c.wantLimit)
			}
			var res struct {
				Limit int `json:"limit"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.Limit != 77 {
				t.Fatalf("response limit = %d (%v), want the repository's 77", res.Limit, err)
			}
		})
	}
}

func TestListHandlerIgnoresAMalformedOwnerFilterWithoutListAny(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media?filters[owner_user_id]=not-a-uuid", nil, ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 1 {
		t.Fatalf("the service was called %d times, want 1", svc.calls)
	}
}

func TestListHandlerEmptyResultShape(t *testing.T) {
	svc := &serviceDouble{listLimit: defaultListLimit}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media", nil, ""})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rec.Body.String())
	}
	if got := strings.TrimSpace(string(raw["data"])); got != "[]" {
		t.Fatalf("data = %s, want []", got)
	}
	var res struct {
		TotalData  int  `json:"total_data"`
		TotalPages int  `json:"total_pages"`
		NextPage   bool `json:"next_page"`
		PrevPage   bool `json:"prev_page"`
		Limit      int  `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.TotalData != 0 || res.TotalPages != 0 || res.NextPage || res.PrevPage || res.Limit != defaultListLimit {
		t.Fatalf("unexpected envelope %+v", res)
	}
}

func TestListHandler500UsesTheStandardBody(t *testing.T) {
	svc := &serviceDouble{err: errors.New("database down")}
	rec := serve(t, svc, uuid.NewString(), "viewer", request{http.MethodGet, "/media", nil, ""})
	var res struct {
		LogID   string `json:"log_id"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	logID, err := uuid.Parse(res.LogID)
	if err != nil {
		t.Fatalf("log_id %q: %v", res.LogID, err)
	}
	want, _ := json.Marshal(gokit.InternalServerError(logID))
	if got := strings.TrimSpace(rec.Body.String()); got != string(want) {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if strings.Contains(rec.Body.String(), "database down") {
		t.Fatal("the response must not reveal the internal error")
	}
}

func TestMediaErrorsUseAFixedEnvelopeMessagePerStatus(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		target  string
		err     error
		status  int
		message string
		detail  string
	}{
		{"delete of a missing row", http.MethodDelete, "/media/" + uuid.NewString(), domainmedia.ErrNotFound, http.StatusNotFound, gokit.MsgResourceNotFound, "media not found"},
		{"delete of another user's row", http.MethodDelete, "/media/" + uuid.NewString(), domainmedia.ErrMediaForbidden, http.StatusNotFound, gokit.MsgResourceNotFound, "media not found"},
		{"too large", http.MethodDelete, "/media/" + uuid.NewString(), domainmedia.ErrFileTooLarge, http.StatusRequestEntityTooLarge, gokit.MsgRequestTooLarge, domainmedia.ErrFileTooLarge.Error()},
		{"bad content", http.MethodDelete, "/media/" + uuid.NewString(), domainmedia.ErrEmptyFile, http.StatusBadRequest, gokit.MsgInvalidRequest, domainmedia.ErrEmptyFile.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &serviceDouble{err: c.err}
			rec := serve(t, svc, uuid.NewString(), "viewer", request{c.method, c.target, nil, ""})
			if rec.Code != c.status || envelopeMessage(t, rec) != c.message || errorMessage(t, rec) != c.detail {
				t.Fatalf("got %d %s, want %d message %q detail %q", rec.Code, rec.Body.String(), c.status, c.message, c.detail)
			}
		})
	}
}

type auditDouble struct {
	authkit.AuditService
	mu     sync.Mutex
	events []authkit.AuditEvent
}

func (a *auditDouble) Store(_ context.Context, event authkit.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func TestFailedUploadAuditStoresTheSanitizedName(t *testing.T) {
	audit := &auditDouble{}
	svc := &serviceDouble{maxFileSize: 1024, err: domainmedia.ErrUnsupportedContentType}
	body, ct := multipartBody(t, "file", "../evil\u202Egnp\u200B.exe", []byte("data"))

	rec := serveHandler(t, New(svc, audit, 0, 0, 0), caller{userID: uuid.NewString(), role: "viewer"}, request{http.MethodPost, "/media", body, ct})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	after, _ := audit.events[0].AfterData.(map[string]any)
	if got := after["original_name"]; got != "evilgnp.exe" {
		t.Fatalf("audited original_name = %q, want the sanitized name", got)
	}
}

type blockingService struct {
	serviceDouble
	entered chan struct{}
	release chan struct{}
}

func (b *blockingService) Upload(_ context.Context, _ string, _ multipart.File, _ *multipart.FileHeader) (domainmedia.Media, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.media, nil
}

func TestUploadsBeyondTheConcurrencyCapAnswer503(t *testing.T) {
	svc := &blockingService{serviceDouble: serviceDouble{maxFileSize: 1024}, entered: make(chan struct{}, 2), release: make(chan struct{})}
	h := New(svc, nil, 0, 1, 0)
	upload := func() *httptest.ResponseRecorder {
		body, ct := multipartBody(t, "file", "a.png", []byte("data"))
		return serveHandler(t, h, caller{userID: uuid.NewString(), role: "viewer"}, request{http.MethodPost, "/media", body, ct})
	}

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- upload() }()
	<-svc.entered

	mark := logs.Mark()
	rec := upload()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("an upload over the cap = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if out := logs.Since(mark); !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("a refused upload is expected traffic, logged at WARN; got:\n%s", out)
	}

	close(svc.release)
	if got := <-first; got.Code != http.StatusCreated {
		t.Fatalf("the first upload = %d: %s", got.Code, got.Body.String())
	}
	if again := upload(); again.Code != http.StatusCreated {
		t.Fatalf("after the slot was freed an upload = %d: %s", again.Code, again.Body.String())
	}
}

func TestClientErrorsAreLoggedAtWarnAndServerErrorsAtError(t *testing.T) {
	cases := []struct {
		name, target string
		perms        []string
		err          error
		wantLevel    string
	}{
		{"bad query", "/media?page=abc", nil, nil, "WARN"},
		{"bad owner filter", "/media?filters[owner_user_id]=x", []string{"media:list_any"}, nil, "WARN"},
		{"not found", "/media", nil, domainmedia.ErrNotFound, "WARN"},
		{"unexpected", "/media", nil, errors.New("database down"), "ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mark := logs.Mark()
			serveWithPermissions(t, &serviceDouble{err: c.err}, caller{uuid.NewString(), "viewer", c.perms}, request{method: http.MethodGet, target: c.target})
			out := logs.Since(mark)
			if !strings.Contains(out, `"level":"`+c.wantLevel+`"`) {
				t.Fatalf("want a %s log line, got:\n%s", c.wantLevel, out)
			}
			if c.wantLevel == "WARN" && strings.Contains(out, `"level":"ERROR"`) {
				t.Fatalf("a client error was logged at ERROR:\n%s", out)
			}
			if !strings.Contains(out, "[MediaHandler][List]") {
				t.Fatalf("the line lacks the handler prefix:\n%s", out)
			}
		})
	}
}

func TestOneUserCannotExhaustTheGlobalUploadSlots(t *testing.T) {
	svc := &blockingService{serviceDouble: serviceDouble{maxFileSize: 1024}, entered: make(chan struct{}, 8), release: make(chan struct{})}
	h := New(svc, nil, 0, 3, 2)
	greedy, other := uuid.NewString(), uuid.NewString()
	upload := func(user string) *httptest.ResponseRecorder {
		body, ct := multipartBody(t, "file", "a.png", []byte("data"))
		return serveHandler(t, h, caller{userID: user, role: "viewer"}, request{http.MethodPost, "/media", body, ct})
	}

	held := make(chan *httptest.ResponseRecorder, 3)
	for range 2 {
		go func() { held <- upload(greedy) }()
		<-svc.entered
	}

	mark := logs.Mark()
	if rec := upload(greedy); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a third concurrent upload of one user = %d, want 429: %s", rec.Code, rec.Body.String())
	}
	if out := logs.Since(mark); !strings.Contains(out, `"level":"WARN"`) || strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("a refused upload is logged at WARN only; got:\n%s", out)
	}

	go func() { held <- upload(other) }()
	<-svc.entered
	close(svc.release)
	for range 3 {
		if got := <-held; got.Code != http.StatusCreated {
			t.Fatalf("a held upload = %d: %s", got.Code, got.Body.String())
		}
	}
	if again := upload(greedy); again.Code != http.StatusCreated {
		t.Fatalf("after the slots were freed the user's upload = %d", again.Code)
	}
}
