package location

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

const provinceBody = `{"data":[{"code":"31","name":"DKI Jakarta"}]}`

func okResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

// jobFixture wires a Service whose sync job "job-1" is stored in a repository
// double and whose HTTP transport is supplied by the test.
func jobFixture(t *testing.T, rt http.RoundTripper) (*Service, *locationRepoTestDouble) {
	t.Helper()
	repo := &locationRepoTestDouble{
		activeJobErr: domainlocation.ErrNotFound,
		syncJob:      domainlocation.SyncJob{ID: "job-1", Status: "queued", Level: "province", CreatedAt: time.Now()},
	}
	svc := NewService(repo, Options{NewID: func() string { return "job-1" }})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc, repo
}

func lastUpdate(t *testing.T, repo *locationRepoTestDouble) domainlocation.SyncJob {
	t.Helper()
	if len(repo.updatedJobs) == 0 {
		t.Fatal("the job was never updated")
	}
	return repo.updatedJobs[len(repo.updatedJobs)-1]
}

func TestCloseCancelsARunningSyncAndMarksItInterrupted(t *testing.T) {
	started := make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))

	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started // the job is inside its HTTP call

	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	got := lastUpdate(t, repo)
	if got.Status != "failed" || got.Message != "Location sync interrupted" || got.ErrorMessage == "" || got.FinishedAt == nil {
		t.Fatalf("the canceled job must end like an interrupted one, got %+v", got)
	}
}

func TestCloseWaitsForTheJobToRecordItsState(t *testing.T) {
	started, observedCancel, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		close(observedCancel)
		<-release // the job is still busy after it noticed the cancellation
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	closed := make(chan error, 1)
	go func() { closed <- svc.Close(context.Background()) }()

	<-observedCancel // Close has canceled the job, which has not finished
	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while the job was still running", err)
	default:
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := lastUpdate(t, repo); got.Status != "failed" || got.Message != "Location sync interrupted" {
		t.Fatalf("job state was not recorded before Close returned: %+v", got)
	}
}

func TestCloseIsBoundedByItsContext(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	svc, _ := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release // ignores cancellation, like a stuck call
		return nil, errors.New("late")
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v, want it to give up with the context error", err)
	}
	close(release)
	if err := svc.Close(context.Background()); err != nil { // second call joins the job
		t.Fatalf("second Close = %v", err)
	}
}

func TestStartSyncAfterCloseIsRefused(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{})
	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); !errors.Is(err, ErrClosed) {
		t.Fatalf("StartSync after Close = %v, want ErrClosed", err)
	}
	if repo.createdJob != nil {
		t.Fatal("no job may be created after Close")
	}
}

func TestCloseWithoutJobsReturnsAtOnceAndIsIdempotent(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{}, Options{})
	for i := 0; i < 2; i++ {
		if err := svc.Close(context.Background()); err != nil {
			t.Fatalf("Close #%d = %v", i+1, err)
		}
	}
}

func TestACompletedSyncIsNotMarkedInterrupted(t *testing.T) {
	svc, repo := jobFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(provinceBody), nil
	}))
	svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province"})
	if got := lastUpdate(t, repo); got.Status != "completed" {
		t.Fatalf("got %+v, want completed", got)
	}
}

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

// deadlineRepo records the deadline of the context each settle write
// received.
type deadlineRepo struct {
	*locationRepoTestDouble
	updateDeadlines []time.Time
}

func (r *deadlineRepo) UpdateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	dl, _ := ctx.Deadline()
	r.updateDeadlines = append(r.updateDeadlines, dl)
	return r.locationRepoTestDouble.UpdateSyncJob(ctx, job)
}

func stuckJobService(t *testing.T, rt http.RoundTripper) (*Service, *deadlineRepo) {
	t.Helper()
	repo := &deadlineRepo{locationRepoTestDouble: &locationRepoTestDouble{
		activeJobErr: domainlocation.ErrNotFound,
		syncJob:      domainlocation.SyncJob{ID: "job-1", Status: "queued", Level: "province", CreatedAt: time.Now()},
	}}
	svc := NewService(repo, Options{NewID: func() string { return "job-1" }})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc, repo
}

func TestSettleWriteUsesWhatRemainsOfTheCloseDeadline(t *testing.T) {
	started := make(chan struct{})
	svc, repo := stuckJobService(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	deadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := svc.Close(ctx); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if len(repo.updateDeadlines) == 0 {
		t.Fatal("the job recorded no final state")
	}
	for _, dl := range repo.updateDeadlines {
		if dl.After(deadline) {
			t.Fatalf("settle write deadline %s is past the Close deadline %s", dl, deadline)
		}
	}
}

func TestSettleWriteIsSkippedOnceTheCloseDeadlineHasPassed(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	svc, repo := stuckJobService(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release // ignores cancellation until after Close gave up
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started
	before := len(repo.updatedJobs) // the job's own progress writes, before shutdown

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := svc.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want the deadline error", err)
	}
	close(release)
	_ = svc.Close(context.Background()) // joins the job
	if n := len(repo.updatedJobs) - before; n != 0 {
		t.Fatalf("the job wrote %d updates after the shutdown deadline", n)
	}
}
