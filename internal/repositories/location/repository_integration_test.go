package location

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/testutil/pgtest"
)

// These tests run against the PostgreSQL named by STARTER_KIT_TEST_DATABASE_URL
// and are skipped without it.

func newJob(owner string, heartbeat time.Time) *domainlocation.SyncJob {
	return &domainlocation.SyncJob{
		ID: uuid.NewString(), Status: "queued", Level: "all", Message: "queued",
		CreatedAt: time.Now(), OwnerInstanceID: owner, HeartbeatAt: heartbeat,
	}
}

func TestIntegrationOnlyOneJobCanBeActive(t *testing.T) {
	repo := NewRepository(pgtest.Open(t))
	ctx := context.Background()

	first := newJob("a", time.Now())
	if err := repo.CreateSyncJob(ctx, first); err != nil {
		t.Fatalf("first job: %v", err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b", time.Now())); !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("a second active job = %v, want ErrSyncRunning from the unique index", err)
	}
	if err := repo.StartSyncJob(ctx, first.ID, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b", time.Now())); !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("a job while one is running = %v, want ErrSyncRunning", err)
	}
	active, err := repo.GetActiveSyncJob(ctx)
	if err != nil || active.ID != first.ID {
		t.Fatalf("active = %+v, %v", active, err)
	}

	if err := repo.FinishSyncJob(ctx, first.ID, "a", domainlocation.SyncFinish{Status: "completed", Message: "done"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b", time.Now())); err != nil {
		t.Fatalf("a job after the first finished: %v", err)
	}
}

func TestIntegrationJobUpdatesAreScopedToTheOwnerAndTheirColumns(t *testing.T) {
	repo := NewRepository(pgtest.Open(t))
	ctx := context.Background()
	job := newJob("a", time.Now())
	if err := repo.CreateSyncJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	if err := repo.StartSyncJob(ctx, job.ID, "intruder", time.Now()); !errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("another instance started the job: %v", err)
	}
	if err := repo.StartSyncJob(ctx, job.ID, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveSyncProgress(ctx, job.ID, "a", domainlocation.SyncProgress{Message: "halfway", CityCount: 7}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetSyncJobByID(ctx, job.ID)
	if err != nil || got.Status != "running" || got.Message != "halfway" || got.CityCount != 7 || got.StartedAt == nil || got.Level != "all" {
		t.Fatalf("after progress: %+v, %v", got, err)
	}

	if err := repo.FinishSyncJob(ctx, job.ID, "a", domainlocation.SyncFinish{Status: "failed", Message: "Location sync failed", ErrorMessage: "boom"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A late write from the same instance must not reopen or change a finished job.
	if err := repo.SaveSyncProgress(ctx, job.ID, "a", domainlocation.SyncProgress{Message: "late", CityCount: 99}, time.Now()); !errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("progress after finish = %v, want ErrNotFound", err)
	}
	got, _ = repo.GetSyncJobByID(ctx, job.ID)
	if got.Status != "failed" || got.ErrorMessage != "boom" || got.CityCount != 7 || got.FinishedAt == nil {
		t.Fatalf("a finished job changed: %+v", got)
	}
}

func TestIntegrationOnlyStaleHeartbeatsAreTakenOver(t *testing.T) {
	db := pgtest.Open(t)
	repo := NewRepository(db)
	ctx := context.Background()
	now := time.Now()

	stale := newJob("dead", now.Add(-10*time.Minute))
	if err := repo.CreateSyncJob(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if err := repo.FailStaleSyncJobs(ctx, now.Add(-2*time.Minute), now, "stopped"); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetSyncJobByID(ctx, stale.ID)
	if got.Status != "failed" || got.ErrorMessage != "stopped" {
		t.Fatalf("a stale job was not taken over: %+v", got)
	}

	live := newJob("alive", now.Add(-30*time.Second))
	if err := repo.CreateSyncJob(ctx, live); err != nil {
		t.Fatalf("the slot was not freed by the takeover: %v", err)
	}
	if err := repo.FailStaleSyncJobs(ctx, now.Add(-2*time.Minute), now, "stopped"); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetSyncJobByID(ctx, live.ID)
	if got.Status != "queued" {
		t.Fatalf("a job with a fresh heartbeat was taken over: %+v", got)
	}
	if err := repo.TouchSyncJob(ctx, live.ID, "alive", now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if err := repo.TouchSyncJob(ctx, stale.ID, "dead", now); !errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("a finished job accepted a heartbeat: %v", err)
	}
}

func TestIntegrationUpsertsAreIdempotentAndUpdateNames(t *testing.T) {
	repo := NewRepository(pgtest.Open(t))
	ctx := context.Background()
	for _, name := range []string{"Aceh", "Nanggroe Aceh"} {
		if err := repo.UpsertProvinces(ctx, []domainlocation.Province{{Code: "11", Name: name}}); err != nil {
			t.Fatalf("upsert %q: %v", name, err)
		}
	}
	rows, err := repo.ListProvinces(ctx)
	if err != nil || len(rows) != 1 || rows[0].Name != "Nanggroe Aceh" {
		t.Fatalf("provinces = %+v, %v", rows, err)
	}
	if _, err := repo.GetProvinceByCode(ctx, "11"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetProvinceByCode(ctx, "99"); !errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("unknown province = %v", err)
	}
	if err := repo.UpsertCities(ctx, nil); err != nil {
		t.Fatalf("empty upsert: %v", err)
	}
}

// The migrations create the owner and heartbeat columns and the unique index,
// and seed the permission with the conflict target the live-name index needs.
func TestIntegrationMigrationShape(t *testing.T) {
	db := pgtest.Open(t)
	var n int64
	db.Raw(`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'ux_location_sync_jobs_one_active'`).Scan(&n)
	if n != 1 {
		t.Fatal("the unique partial index on active sync jobs is missing")
	}
	for _, column := range []string{"owner_instance_id", "heartbeat_at"} {
		db.Raw(`SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'location_sync_jobs' AND column_name = ?`, column).Scan(&n)
		if n != 1 {
			t.Fatalf("location_sync_jobs.%s is missing", column)
		}
	}
	db.Raw(`SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'location_sync_jobs' AND column_name = 'year'`).Scan(&n)
	if n != 0 {
		t.Fatal("the year column must be gone")
	}
	db.Raw(`SELECT count(*) FROM permissions WHERE name = 'sync_locations' AND deleted_at IS NULL`).Scan(&n)
	if n != 1 {
		t.Fatalf("sync_locations permission rows = %d, want 1", n)
	}
}

// Applying a migration twice must not fail or duplicate the seeds.
func TestIntegrationMigrationsCanBeAppliedTwice(t *testing.T) {
	db := pgtest.Open(t)
	for _, file := range pgtest.MigrationFiles(t, ".up.sql") {
		body, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(string(body)).Error; err != nil {
			t.Fatalf("second apply of %s: %v", file, err)
		}
	}
	var n int64
	db.Raw(`SELECT count(*) FROM permissions WHERE name IN ('sync_locations', 'list_any_media', 'delete_any_media')`).Scan(&n)
	if n != 3 {
		t.Fatalf("seeded permissions = %d, want 3", n)
	}
}
