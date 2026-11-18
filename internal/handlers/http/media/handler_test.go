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
	gin.SetMode(gin.TestMode)
	h := New(svc, nil, 0)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		scope := authkit.NewScope(userID, "tester", role, nil)
		c.Request = c.Request.WithContext(authkit.WithScope(c.Request.Context(), scope))
	})
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
			if rec.Code != c.status || errorMessage(t, rec) != c.message {
				t.Fatalf("got %d %s, want %d %q", rec.Code, rec.Body.String(), c.status, c.message)
			}
			if strings.Contains(rec.Body.String(), "connection refused") {
				t.Fatal("the response must not reveal the internal error")
			}
		})
	}
}

func TestDeleteHandlerBuildsTheActorFromTheScope(t *testing.T) {
	id := uuid.NewString()
	user := uuid.NewString()
	cases := []struct {
		role      string
		superuser bool
	}{
		{"viewer", false},
		{authkit.RoleSuperAdmin, true},
		{" " + authkit.RoleSuperAdmin + " ", true},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			svc := &serviceDouble{media: domainmedia.Media{ID: id}}
			rec := serve(t, svc, user, c.role, http.MethodDelete, "/media/"+id, nil, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if svc.deleteID != id || svc.deleteActor != (domainmedia.Actor{UserID: user, IsSuperAdmin: c.superuser}) {
				t.Fatalf("service got id %q actor %+v", svc.deleteID, svc.deleteActor)
			}
		})
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
