package location

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

const provinceBody = `{"data":[{"code":"31","name":"DKI Jakarta"}]}`

// jobFixture wires a Service whose HTTP transport is supplied by the test.
func jobFixture(t *testing.T, rt http.RoundTripper) (*Service, *locationRepoTestDouble) {
	t.Helper()
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{NewID: func() string { return "job-1" }, HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc, repo
}

func TestCloseCancelsARunningSyncAndMarksItInterrupted(t *testing.T) {
	started := make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))

	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started // the job is inside its HTTP call

	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	got := repo.lastFinish(t)
	if got.Status != "failed" || got.Message != "Location sync interrupted" || got.ErrorMessage != shutdownMessage {
		t.Fatalf("the canceled job must end like an interrupted one, got %+v", got)
	}
}

// Interrupt only signals: the shutdown goes on and the job records its end
// while the HTTP requests drain, so a long drain cannot starve the final write.
func TestInterruptCancelsTheJobWithoutWaitingForIt(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		<-release
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	returned := make(chan struct{})
	go func() { svc.Interrupt(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Interrupt waited for the job")
	}
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); !errors.Is(err, domainlocation.ErrShuttingDown) {
		t.Fatalf("StartSync after Interrupt = %v, want ErrShuttingDown", err)
	}

	close(release)
	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := repo.lastFinish(t); got.Message != "Location sync interrupted" {
		t.Fatalf("final state = %+v", got)
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
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
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
	if got := repo.lastFinish(t); got.Status != "failed" || got.Message != "Location sync interrupted" {
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
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
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
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{})
	if err := svc.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); !errors.Is(err, domainlocation.ErrShuttingDown) {
		t.Fatalf("StartSync after Close = %v, want ErrShuttingDown", err)
	}
	if repo.createdJob != nil || len(repo.failStale) != 0 {
		t.Fatal("nothing may be written after Close")
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
	svc, repo := jobFixture(t, answering(provinceBody))
	svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province"})
	if got := repo.lastFinish(t); got.Status != "completed" {
		t.Fatalf("got %+v, want completed", got)
	}
}

func TestNewServiceDoesNotTouchTheRepository(t *testing.T) {
	repo := &locationRepoTestDouble{}
	_ = NewService(repo, Options{})
	if len(repo.failStale) != 0 {
		t.Fatal("the constructor wrote to the repository")
	}
}

// Recovery fails only jobs whose heartbeat is older than StaleAfter: a job of
// an instance that is still alive (a rolling deploy) is not touched.
func TestRecoverInterruptedJobsTakesOverOnlyStaleJobs(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{StaleAfter: 90 * time.Second})
	if err := svc.RecoverInterruptedJobs(context.Background()); err != nil {
		t.Fatalf("RecoverInterruptedJobs = %v", err)
	}
	if len(repo.failStale) != 1 {
		t.Fatalf("FailStaleSyncJobs called %d times", len(repo.failStale))
	}
	if repo.failStale[0] != 90*time.Second {
		t.Fatalf("the repository was told %v, want the 90s StaleAfter, so younger heartbeats are kept", repo.failStale[0])
	}
	if repo.failStaleMessage != staleMessage {
		t.Fatalf("unexpected recovery message %q", repo.failStaleMessage)
	}

	boom := errors.New("database down")
	svc = NewService(&locationRepoTestDouble{failStaleErr: boom}, Options{})
	if err := svc.RecoverInterruptedJobs(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("RecoverInterruptedJobs = %v, want it to wrap the repository error", err)
	}
}

func TestSettleWriteUsesWhatRemainsOfTheCloseDeadline(t *testing.T) {
	started := make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	deadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := svc.Close(ctx); err != nil {
		t.Fatalf("Close = %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.deadlines) == 0 {
		t.Fatal("the job recorded no final state")
	}
	for _, dl := range repo.deadlines {
		if dl.After(deadline) {
			t.Fatalf("settle write deadline %s is past the Close deadline %s", dl, deadline)
		}
	}
}

func TestSettleWriteIsSkippedOnceTheCloseDeadlineHasPassed(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	svc, repo := jobFixture(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release // ignores cancellation until after Close gave up
		return nil, req.Context().Err()
	}))
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := svc.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want the deadline error", err)
	}
	close(release)
	_ = svc.Close(context.Background()) // joins the job
	if finishes, _, _ := repo.counts(); finishes != 0 {
		t.Fatalf("the job wrote %d final states after the shutdown deadline", finishes)
	}
}
