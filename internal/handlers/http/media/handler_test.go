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

// serviceDouble records what the handlers pass to the service.
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
}

func (d *serviceDouble) List(_ context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error) {
	d.calls++
	d.listActor, d.listReq = actor, req
	return d.listItems, d.listTotal, d.err
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

// serve mounts the handler behind a middleware that installs the authenticated
// scope, then performs one request.
func serve(t *testing.T, svc Service, userID, role, method, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	return serveWithPermissions(t, svc, userID, role, nil, method, target, body, contentType)
}

// serveWithPermissions is serve for a caller holding permissions, each written
// as "resource:action".
func serveWithPermissions(t *testing.T, svc Service, userID, role string, permissions []string, method, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := New(svc, nil, 0)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		scope := authkit.NewScope(userID, "tester", role, permissions)
		c.Request = c.Request.WithContext(authkit.WithScope(c.Request.Context(), scope))
	})
	engine.GET("/media", h.List)
	engine.POST("/media", h.Upload)
	engine.DELETE("/media/:id", h.Delete)

	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
		Error any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rec.Body.String())
	}
	switch e := res.Error.(type) {
	case string:
		return e
	case map[string]any:
		msg, _ := e["message"].(string)
		return msg
	}
	return ""
}

func TestUploadHandlerPassesTheAuthenticatedUserToTheService(t *testing.T) {
	owner := uuid.NewString()
	svc := &serviceDouble{maxFileSize: 1024, media: domainmedia.Media{ID: "media-1", OwnerUserID: owner}}
	body, ct := multipartBody(t, "file", "a.png", []byte("data"))

	rec := serve(t, svc, owner, "viewer", http.MethodPost, "/media", body, ct)

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

	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodPost, "/media", body, ct)

	if rec.Code != http.StatusBadRequest || errorMessage(t, rec) != "file is required" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 0 {
		t.Fatal("the service must not be called without a file")
	}
}

func TestUploadHandlerAnswers413ForABodyOverTheLimit(t *testing.T) {
	svc := &serviceDouble{maxFileSize: 10}
	// The limit is the service's maximum plus the multipart overhead allowance.
	body, ct := multipartBody(t, "file", "big.png", bytes.Repeat([]byte("x"), int(multipartOverhead)+1024))

	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodPost, "/media", body, ct)

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
			rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodPost, "/media", body, ct)
			if c.status == http.StatusInternalServerError {
				// gokit.InternalServerError: generic text plus the log ID.
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
	rec := serveWithPermissions(t, svc, user, "viewer", []string{"media:delete_any"}, http.MethodDelete, "/media/"+id, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.deleteID != id || svc.deleteActor != (domainmedia.Actor{UserID: user, CanDeleteAny: true}) {
		t.Fatalf("service got id %q actor %+v", svc.deleteID, svc.deleteActor)
	}
}

func TestDeleteHandlerRejectsAnInvalidID(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodDelete, "/media/not-a-uuid", nil, "")
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
			rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodDelete, "/media/"+id, nil, "")
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, c.status, rec.Body.String())
			}
		})
	}
}

func TestListHandlerRejectsABadPageNumber(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media?page=abc", nil, "")
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
			rec := serveWithPermissions(t, svc, uuid.NewString(), "viewer", []string{"media:list_any"}, http.MethodGet, target, nil, "")
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
	rec := serve(t, svc, user, "viewer", http.MethodGet, "/media", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	want := dtomedia.ListRequest{Page: 1, Limit: 20} // the default order is the repository's
	if svc.listReq != want {
		t.Fatalf("defaults: got %+v, want %+v", svc.listReq, want)
	}
	if svc.listActor != (domainmedia.Actor{UserID: user}) {
		t.Fatalf("actor = %+v", svc.listActor)
	}

	target := "/media?search=cat&page=3&limit=5&order_by=size&order_direction=asc" +
		"&filters[owner_user_id]=" + other + "&filters[content_type]=image/png&filters[object_key]=secret"
	svc = &serviceDouble{}
	if rec := serve(t, svc, user, "viewer", http.MethodGet, target, nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	want = dtomedia.ListRequest{
		Search: "cat", OwnerUserID: other, ContentType: "image/png",
		OrderBy: "size", OrderDirection: "asc", Page: 3, Limit: 5, Offset: 10,
	}
	if svc.listReq != want {
		t.Fatalf("got %+v, want %+v", svc.listReq, want)
	}
}

func TestListHandlerRespondsWithThePaginationShape(t *testing.T) {
	svc := &serviceDouble{listItems: []domainmedia.Media{{ID: "m-1", OwnerUserID: "u-1"}}, listTotal: 41}
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media?limit=20&page=2", nil, "")
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
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media", nil, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

// A user-facing list is bounded: gokit keeps limit=-1 (no limit) and accepts
// up to 10000, so the handler clamps before the service sees the value.
func TestListHandlerClampsTheLimit(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		// gokit resets the page to 1 for -1, so the offset is 0.
		{"minus one is not unbounded", "limit=-1&page=3", defaultListLimit, 0},
		{"zero falls back", "limit=0", defaultListLimit, 0},
		{"above the maximum", "limit=101&page=2", maxListLimit, maxListLimit},
		{"huge value", "limit=10000", maxListLimit, 0},
		{"normal value", "limit=5&page=3", 5, 10},
		{"the maximum itself", "limit=100", maxListLimit, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &serviceDouble{}
			rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media?"+c.query, nil, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if svc.listReq.Limit != c.wantLimit || svc.listReq.Offset != c.wantOffset {
				t.Fatalf("limit/offset = %d/%d, want %d/%d", svc.listReq.Limit, svc.listReq.Offset, c.wantLimit, c.wantOffset)
			}
			var res struct {
				Limit int `json:"limit"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.Limit != c.wantLimit {
				t.Fatalf("response limit = %d (%v), want %d", res.Limit, err, c.wantLimit)
			}
		})
	}
}

// Without media:list_any the owner filter is ignored (the service forces the
// caller's own id), so a malformed value must not turn into a 400.
func TestListHandlerIgnoresAMalformedOwnerFilterWithoutListAny(t *testing.T) {
	svc := &serviceDouble{}
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media?filters[owner_user_id]=not-a-uuid", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if svc.calls != 1 {
		t.Fatalf("the service was called %d times, want 1", svc.calls)
	}
}

// An empty page still has the full envelope: data is [], never null, and the
// totals are zero.
func TestListHandlerEmptyResultShape(t *testing.T) {
	svc := &serviceDouble{} // nil items, total 0
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media", nil, "")
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

// Every plain 500 uses gokit.InternalServerError: a generic message and the
// log ID for support, with no internal detail.
func TestListHandler500UsesTheStandardBody(t *testing.T) {
	svc := &serviceDouble{err: errors.New("database down")}
	rec := serve(t, svc, uuid.NewString(), "viewer", http.MethodGet, "/media", nil, "")
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
