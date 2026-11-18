package media

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"

	"starter-kit/internal/config"
	"starter-kit/internal/router/module"
	"starter-kit/internal/testutil/routertest"
)

// engineFor mounts the media module alone under /api.
func engineFor(t *testing.T, d module.Deps) *gin.Engine {
	t.Helper()
	return routertest.Mount(t, Register, d)
}

// mediaRoutes is every route the module mounts, pinned on purpose: a new route
// must be added here and, if it is protected, to TestMediaRoutesProtection.
var mediaRoutes = []string{
	"DELETE /api/media/:id",
	"GET /api/media",
	"POST /api/media",
}

func TestMediaMountsExactlyItsRoutes(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = true })
		d.Storage = routertest.FakeStorage{}
		got := routertest.SortedKeys(routertest.RouteSet(engineFor(t, d)))
		if strings.Join(got, "\n") != strings.Join(mediaRoutes, "\n") {
			t.Fatalf("routes are\n  %v\nwant\n  %v", got, mediaRoutes)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = false })
		if got := routertest.RouteSet(engineFor(t, d)); len(got) != 0 {
			t.Fatalf("disabled media mounted %v", got)
		}
	})
}

func TestMediaRoutesProtection(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		engine := engineFor(t, routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = false }))
		if got := routertest.Serve(engine, http.MethodPost, "/api/media"); got != http.StatusNotFound {
			t.Fatalf("expected 404 when media disabled, got %d", got)
		}
	})

	t.Run("disabled registers nothing even when a provider is passed", func(t *testing.T) {
		d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = false })
		d.Storage = routertest.FakeStorage{}
		for _, route := range engineFor(t, d).Routes() {
			if strings.HasPrefix(route.Path, "/api/media") {
				t.Fatalf("media route %s registered while media is disabled", route.Path)
			}
		}
	})

	t.Run("enabled", func(t *testing.T) {
		d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = true })
		d.Storage = routertest.FakeStorage{}
		engine := engineFor(t, d)
		if got := routertest.Serve(engine, http.MethodPost, "/api/media"); got != http.StatusUnauthorized {
			t.Fatalf("POST /api/media without token: expected 401, got %d", got)
		}
		if got := routertest.Serve(engine, http.MethodDelete, "/api/media/abc"); got != http.StatusUnauthorized {
			t.Fatalf("DELETE /api/media/abc without token: expected 401, got %d", got)
		}
		if got := routertest.Serve(engine, http.MethodGet, "/api/media"); got != http.StatusUnauthorized {
			t.Fatalf("GET /api/media without token: expected 401, got %d", got)
		}
	})
}

func mediaDeps(t *testing.T) module.Deps {
	t.Helper()
	d := routertest.NewDeps(t, func(c *config.Config) {
		c.Media.Enabled = true
		c.Media.MaxFileSizeBytes = 64 << 10
		c.HTTP.MaxBodyBytes = 1 << 20
	})
	d.Storage = routertest.FakeStorage{}
	return d
}

func uploadRequest(t *testing.T, d module.Deps, fileSize int) *http.Request {
	t.Helper()
	token, err := d.Kit.IssueAccessToken("11111111-1111-1111-1111-111111111111", "", "viewer")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="file"; filename="a.png"`)
	hdr.Set("Content-Type", "image/png")
	part, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, fileSize)
	copy(data, []byte("\x89PNG\r\n\x1a\n"))
	_, _ = part.Write(data)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/media", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestMediaUploadAtMaxSizeIsAccepted(t *testing.T) {
	d := mediaDeps(t)
	engine := engineFor(t, d)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, uploadRequest(t, d, 64<<10))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload at max size: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
	calls    int
}

func (r *deadlineRecorder) SetReadDeadline(t time.Time) error {
	r.deadline = t
	r.calls++
	return nil
}

func TestMediaUploadExtendsReadDeadline(t *testing.T) {
	d := mediaDeps(t)
	d.Config.Media.UploadTimeout = 90 * time.Second
	engine := engineFor(t, d)
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	engine.ServeHTTP(rec, uploadRequest(t, d, 1024))
	if rec.calls == 0 {
		t.Fatal("upload handler did not extend the read deadline")
	}
	if diff := time.Until(rec.deadline) - d.Config.Media.UploadTimeout; diff > time.Second || diff < -time.Second {
		t.Fatalf("deadline is %s away from now+UploadTimeout", diff)
	}
}

// With Auth passing and no such user in the database, LoadPermissions answers
// 403 before the handler runs; a route without it would reach the service. The
// user lookup is asserted too, so the 403 cannot come from anywhere else.
func TestMediaListAndDeleteLoadPermissionsAfterAuth(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/media"},
		{http.MethodDelete, "/api/media/22222222-2222-2222-2222-222222222222"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			d := mediaDeps(t)
			db, mock := routertest.NewExecDB(t)
			kit, err := authkit.New(authkit.Config{DB: db, AppName: "starter-kit-test", JWTKey: "test-jwt-key-that-is-at-least-32-characters-long"})
			if err != nil {
				t.Fatalf("authkit.New: %v", err)
			}
			d.DB, d.Kit = db, kit
			mock.ExpectQuery(`FROM "blacklist"`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			mock.ExpectQuery(`FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

			token, err := kit.IssueAccessToken("11111111-1111-1111-1111-111111111111", "", "viewer")
			if err != nil {
				t.Fatalf("token: %v", err)
			}
			req := httptest.NewRequest(c.method, c.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			engineFor(t, d).ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 from LoadPermissions, got %d: %s", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("permission lookup did not run: %v", err)
			}
		})
	}
}

func TestMediaUploadSkipsLoadPermissions(t *testing.T) {
	d := mediaDeps(t)
	rec := httptest.NewRecorder()
	engineFor(t, d).ServeHTTP(rec, uploadRequest(t, d, 1024))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload must not need a permission lookup, got %d: %s", rec.Code, rec.Body.String())
	}
}
