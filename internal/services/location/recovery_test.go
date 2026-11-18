package location

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func TestNewServiceDoesNotTouchTheRepository(t *testing.T) {
	repo := &locationRepoTestDouble{}
	_ = NewService(repo, Options{})
	if repo.failMessage != "" {
		t.Fatalf("the constructor wrote to the repository: %q", repo.failMessage)
	}
}

func TestRecoverInterruptedJobsFailsActiveJobs(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{})
	if err := svc.RecoverInterruptedJobs(context.Background()); err != nil {
		t.Fatalf("RecoverInterruptedJobs = %v", err)
	}
	if repo.failMessage != "Service restarted before the previous location sync completed." {
		t.Fatalf("unexpected recovery message %q", repo.failMessage)
	}

	boom := errors.New("database down")
	svc = NewService(&locationRepoTestDouble{failActiveErr: boom}, Options{})
	if err := svc.RecoverInterruptedJobs(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("RecoverInterruptedJobs = %v, want it to wrap the repository error", err)
	}
}

func TestStartSyncUsesInjectedIDAndRequester(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{NewID: func() string { return "job-fixed" }})

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "user-9")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if got.ID != "job-fixed" || repo.createdJob.ID != "job-fixed" || repo.createdJob.RequestedBy != "user-9" {
		t.Fatalf("job = %+v, created = %+v", got, repo.createdJob)
	}
}

// Without an injected generator the service issues UUIDv7 ids, the version
// gokit.CreateUUID produces, so job ids stay time-ordered.
func TestDefaultJobIDIsUUIDv7(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{})

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if id, err := uuid.Parse(got.ID); err != nil || id.Version() != 7 {
		t.Fatalf("job id %q is not a UUIDv7 (err=%v)", got.ID, err)
	}
}
