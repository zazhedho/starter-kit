package location

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
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
	d := routertest.NewDeps(t, nil)
	w, err := wire(d)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	d.Lifecycle.Drain()
	if _, err := w.service.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); !errors.Is(err, domainlocation.ErrShuttingDown) {
		t.Fatalf("StartSync after Drain = %v, want ErrShuttingDown: the drain hook is not registered", err)
	}
	if err := d.Lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("Lifecycle.Close = %v", err)
	}
}
