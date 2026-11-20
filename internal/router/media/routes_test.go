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
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"

	"starter-kit/internal/config"
	"starter-kit/internal/router/module"
	"starter-kit/internal/testutil/routertest"
)

func engineFor(t *testing.T, d module.Deps) *gin.Engine {
	t.Helper()
	return routertest.Mount(t, Register, d)
}

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

const (
	testUserID = "11111111-1111-1111-1111-111111111111"
	testJWTKey = "test-jwt-key-that-is-at-least-32-characters-long"
)

func authedDeps(t *testing.T) (module.Deps, sqlmock.Sqlmock) {
	t.Helper()
	d := mediaDeps(t)
	db, mock := routertest.NewExecDB(t)
	kit, err := authkit.New(authkit.Config{DB: db, AppName: "starter-kit-test", JWTKey: testJWTKey})
	if err != nil {
		t.Fatalf("authkit.New: %v", err)
	}
	d.DB, d.Kit = db, kit
	expectAuth(mock)
	return d, mock
}

func expectAuth(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM "blacklist"`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}))
	mock.ExpectQuery(`FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"role", "tokens_valid_after"}).AddRow("viewer", nil))
}

func uploadRequest(t *testing.T, d module.Deps, fileSize int) *http.Request {
	t.Helper()
	return uploadRequestAs(t, d, testUserID, fileSize)
}

func uploadRequestAs(t *testing.T, d module.Deps, userID string, fileSize int) *http.Request {
	t.Helper()
	token, err := d.Kit.IssueAccessToken(userID, "", "viewer")
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
	d, mock := authedDeps(t)
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
	engine := engineFor(t, d)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, uploadRequest(t, d, 64<<10))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload at max size: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline      time.Time
	calls         int
	writeDeadline time.Time
	writeCalls    int
}

func (r *deadlineRecorder) SetReadDeadline(t time.Time) error {
	r.deadline = t
	r.calls++
	return nil
}

func (r *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	r.writeDeadline = t
	r.writeCalls++
	return nil
}

func TestMediaUploadExtendsTheReadAndWriteDeadlines(t *testing.T) {
	d, mock := authedDeps(t)
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
	d.Config.Media.UploadTimeout = 90 * time.Second
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	engineFor(t, d).ServeHTTP(rec, uploadRequest(t, d, 1024))
	for name, c := range map[string]struct {
		calls    int
		deadline time.Time
	}{"read": {rec.calls, rec.deadline}, "write": {rec.writeCalls, rec.writeDeadline}} {
		if c.calls == 0 {
			t.Fatalf("upload handler did not extend the %s deadline", name)
		}
		if diff := time.Until(c.deadline) - d.Config.Media.UploadTimeout; diff > time.Second || diff < -time.Second {
			t.Fatalf("%s deadline is %s away from now+UploadTimeout", name, diff)
		}
	}
}

func TestMediaListAndDeleteLoadPermissionsAfterAuth(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/media"},
		{http.MethodDelete, "/api/media/22222222-2222-2222-2222-222222222222"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			d, mock := authedDeps(t)
			mock.ExpectQuery(`FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

			token, err := d.Kit.IssueAccessToken(testUserID, "", "viewer")
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
	d, mock := authedDeps(t)
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
	rec := httptest.NewRecorder()
	engineFor(t, d).ServeHTTP(rec, uploadRequest(t, d, 1024))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload must not need a permission lookup, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMediaWithoutRedisSkipsTheUploadLimiter(t *testing.T) {
	d := routertest.NewDeps(t, func(c *config.Config) {
		c.Media.Enabled = true
		c.Media.UploadRateLimit = 0
		c.Media.UploadRateWindow = 0
		c.Media.UserUploadLimit = 0
		c.Media.UserUploadWindow = 0
	})
	d.Storage = routertest.FakeStorage{}
	d.Redis = nil
	engineFor(t, d)
}

func TestMediaWithRedisBuildsTheUploadLimiter(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	d, mock := authedDeps(t)
	d.Redis = client
	d.Config.Media.UploadRateLimit = 1
	d.Config.Media.UploadRateWindow = time.Minute
	engine := engineFor(t, d)

	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
	first := httptest.NewRecorder()
	engine.ServeHTTP(first, uploadRequest(t, d, 1024))
	if first.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", first.Code, first.Body.String())
	}

	expectAuth(mock)
	second := httptest.NewRecorder()
	engine.ServeHTTP(second, uploadRequest(t, d, 1024))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second upload = %d, want 429: %s", second.Code, second.Body.String())
	}
}

func TestMediaUploadIsLimitedPerUser(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	d, mock := authedDeps(t)
	d.Redis = client
	d.Config.Media.UploadRateLimit = 100
	d.Config.Media.UploadRateWindow = time.Minute
	d.Config.Media.UserUploadLimit = 1
	d.Config.Media.UserUploadWindow = time.Minute
	engine := engineFor(t, d)
	other := "22222222-2222-2222-2222-222222222222"

	upload := func(userID string, wantInsert bool) int {
		if wantInsert {
			mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, uploadRequestAs(t, d, userID, 1024))
		return rec.Code
	}

	if got := upload(testUserID, true); got != http.StatusCreated {
		t.Fatalf("first upload of the user = %d", got)
	}
	expectAuth(mock)
	if got := upload(testUserID, false); got != http.StatusTooManyRequests {
		t.Fatalf("second upload of the same user = %d, want 429", got)
	}
	expectAuth(mock)
	if got := upload(other, true); got != http.StatusCreated {
		t.Fatalf("first upload of another user = %d, want 201: the limit is per user", got)
	}
}

func TestMediaUploadFollowsTheFailClosedSetting(t *testing.T) {
	for _, c := range []struct {
		failClosed bool
		want       int
	}{{false, http.StatusCreated}, {true, http.StatusServiceUnavailable}} {
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })

		d, mock := authedDeps(t)
		d.Redis = client
		d.Config.Auth.FailClosedLimiters = c.failClosed
		d.Config.Media.UploadRateLimit, d.Config.Media.UploadRateWindow = 5, time.Minute
		d.Config.Media.UserUploadLimit, d.Config.Media.UserUploadWindow = 5, time.Minute
		engine := engineFor(t, d)
		mr.Close()
		if !c.failClosed {
			mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, uploadRequest(t, d, 1024))
		if rec.Code != c.want {
			t.Fatalf("fail closed = %v: got %d, want %d: %s", c.failClosed, rec.Code, c.want, rec.Body.String())
		}
	}
}
