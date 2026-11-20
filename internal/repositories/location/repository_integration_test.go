package location

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/testutil/pgtest"
)

func newJob(owner string) *domainlocation.SyncJob {
	return &domainlocation.SyncJob{
		ID: uuid.NewString(), Status: "queued", Level: "all", Message: "queued", RequestedBy: uuid.NewString(),
		CreatedAt: time.Now(), OwnerInstanceID: owner,
	}
}

func ageHeartbeat(t *testing.T, db *gorm.DB, id string, age time.Duration) {
	t.Helper()
	if err := db.Exec(`UPDATE location_sync_jobs SET heartbeat_at = now() - make_interval(secs => ?) WHERE id = ?`, age.Seconds(), id).Error; err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationOnlyOneJobCanBeActive(t *testing.T) {
	repo := NewRepository(pgtest.Open(t))
	ctx := context.Background()

	first := newJob("a")
	if err := repo.CreateSyncJob(ctx, first); err != nil {
		t.Fatalf("first job: %v", err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b")); !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("a second active job = %v, want ErrSyncRunning from the unique index", err)
	}
	if err := repo.StartSyncJob(ctx, first.ID, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b")); !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("a job while one is running = %v, want ErrSyncRunning", err)
	}
	active, err := repo.GetActiveSyncJob(ctx)
	if err != nil || active.ID != first.ID {
		t.Fatalf("active = %+v, %v", active, err)
	}

	if err := repo.FinishSyncJob(ctx, first.ID, "a", domainlocation.SyncFinish{Status: "completed", Message: "done"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSyncJob(ctx, newJob("b")); err != nil {
		t.Fatalf("a job after the first finished: %v", err)
	}
}

func TestIntegrationJobUpdatesAreScopedToTheOwnerAndTheirColumns(t *testing.T) {
	repo := NewRepository(pgtest.Open(t))
	ctx := context.Background()
	job := newJob("a")
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

	stale := newJob("dead")
	if err := repo.CreateSyncJob(ctx, stale); err != nil {
		t.Fatal(err)
	}
	ageHeartbeat(t, db, stale.ID, 10*time.Minute)
	if err := repo.FailStaleSyncJobs(ctx, 2*time.Minute, now, "stopped"); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetSyncJobByID(ctx, stale.ID)
	if got.Status != "failed" || got.ErrorMessage != "stopped" {
		t.Fatalf("a stale job was not taken over: %+v", got)
	}

	live := newJob("alive")
	if err := repo.CreateSyncJob(ctx, live); err != nil {
		t.Fatalf("the slot was not freed by the takeover: %v", err)
	}
	ageHeartbeat(t, db, live.ID, 30*time.Second)
	if err := repo.FailStaleSyncJobs(ctx, 2*time.Minute, now, "stopped"); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetSyncJobByID(ctx, live.ID)
	if got.Status != "queued" {
		t.Fatalf("a job with a fresh heartbeat was taken over: %+v", got)
	}
	if err := repo.TouchSyncJob(ctx, live.ID, "alive"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if err := repo.TouchSyncJob(ctx, stale.ID, "dead"); !errors.Is(err, domainlocation.ErrNotFound) {
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

func TestIntegrationHeartbeatUsesTheDatabaseClock(t *testing.T) {
	db := pgtest.Open(t)
	repo := NewRepository(db)
	ctx := context.Background()
	job := newJob("a")
	if err := repo.CreateSyncJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	var created, touched, dbNow time.Time
	db.Raw(`SELECT heartbeat_at FROM location_sync_jobs WHERE id = ?`, job.ID).Scan(&created)
	if time.Since(created) > time.Minute || time.Until(created) > time.Minute {
		t.Fatalf("a new job's heartbeat is %v, want the database's now", created)
	}
	ageHeartbeat(t, db, job.ID, time.Hour)
	if err := repo.TouchSyncJob(ctx, job.ID, "a"); err != nil {
		t.Fatal(err)
	}
	if err := db.Raw(`SELECT heartbeat_at, now() FROM location_sync_jobs WHERE id = ?`, job.ID).Row().Scan(&touched, &dbNow); err != nil {
		t.Fatal(err)
	}
	if dbNow.Sub(touched) > time.Minute || touched.After(dbNow.Add(time.Second)) {
		t.Fatalf("heartbeat %v is not the database's now %v", touched, dbNow)
	}
	if err := repo.FailStaleSyncJobs(ctx, time.Hour, time.Now(), "stopped"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetSyncJobByID(ctx, job.ID); got.Status != "queued" {
		t.Fatalf("a job with a fresh heartbeat was taken over: %+v", got)
	}
}
