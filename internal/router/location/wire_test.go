package location

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"starter-kit/internal/config"
	"starter-kit/internal/testutil/routertest"
)

func TestRegisterLocationRecoversInterruptedJobs(t *testing.T) {
	d := routertest.NewDeps(t, nil)
	db, mock := routertest.NewExecDB(t)
	d.DB = db
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := Register(gin.New(), d); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("interrupted jobs were not recovered by the registrar: %v", err)
	}
}

func TestRegisterLocationReturnsTheRecoveryError(t *testing.T) {
	d := routertest.NewDeps(t, nil)
	db, mock := routertest.NewExecDB(t)
	d.DB = db
	boom := errors.New("database down")
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillReturnError(boom)

	if err := Register(gin.New(), d); !errors.Is(err, boom) {
		t.Fatalf("Register = %v, want it to wrap the recovery error", err)
	}
}

func TestRegisterLocationBoundsStartupRecovery(t *testing.T) {
	old := recoveryTimeout
	recoveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { recoveryTimeout = old })

	d := routertest.NewDeps(t, nil)
	db, mock := routertest.NewExecDB(t)
	d.DB = db
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillDelayFor(time.Hour).WillReturnResult(sqlmock.NewResult(0, 1))

	done := make(chan error, 1)
	go func() { done <- Register(gin.New(), d) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Register succeeded although recovery did not finish")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging recovery was not bounded")
	}
}

// Drain, the first step of shutdown, interrupts the sync service so it stops
// accepting jobs while requests still drain; Close then waits for it.
func TestRegisterLocationRegistersShutdownHooks(t *testing.T) {
	d, _ := signedInDeps(t, "superadmin")
	engine := engineFor(t, d)
	d.Lifecycle.Drain()

	token, err := d.Kit.IssueAccessToken(viewerID, "", "superadmin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/location/sync", strings.NewReader(`{"level":"province"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a sync after Drain = %d, want 503: the drain hook is not registered: %s", rec.Code, rec.Body.String())
	}
	if err := d.Lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("Lifecycle.Close = %v", err)
	}
}

// The configured response cap reaches the service: a body over it is an upstream
// failure (502), not a stored list.
func TestRegisterLocationPassesTheResponseCap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"code":"11","name":"` + strings.Repeat("A", 300) + `"}]`))
	}))
	t.Cleanup(upstream.Close)

	d := routertest.NewDeps(t, func(c *config.Config) {
		c.Location.ServiceBaseURL = upstream.URL
		c.Location.MaxResponseBytes = 100
	})
	db, mock := routertest.NewExecDB(t)
	d.DB = db
	mock.ExpectExec(`UPDATE .location_sync_jobs. SET`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM "provinces"`).WillReturnRows(sqlmock.NewRows([]string{"id"}))

	if got := routertest.Serve(engineFor(t, d), http.MethodGet, "/api/location/province"); got != http.StatusBadGateway {
		t.Fatalf("GET province with an oversized upstream body = %d, want 502", got)
	}
}
