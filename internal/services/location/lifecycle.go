package location

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrClosed is returned by StartSync after Close: the service no longer starts
// background work.
var ErrClosed = errors.New("location service is closed")

// Messages for jobs that did not complete; both match the state FailActiveSyncJobs
// leaves (failed, "Location sync interrupted").
const (
	restartedMessage = "Service restarted before the previous location sync completed."
	shutdownMessage  = "Application shut down before the location sync completed."

	// settleTimeout bounds the final database write of a canceled job, which
	// must not use the canceled context.
	settleTimeout = 10 * time.Second
)

// RecoverInterruptedJobs fails every queued or running job; call once at startup,
// since such jobs belong to a dead process.
func (s *Service) RecoverInterruptedJobs(ctx context.Context) error {
	if err := s.repo.FailActiveSyncJobs(ctx, restartedMessage); err != nil {
		return fmt.Errorf("mark interrupted location sync jobs: %w", err)
	}
	return nil
}

// Close cancels the running sync job and waits until ctx ends or the job returns.
// The job's final write is bounded by ctx's deadline and settleTimeout.
// Safe to call twice; afterwards StartSync fails with ErrClosed.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	if dl, ok := ctx.Deadline(); ok && (s.settleBy.IsZero() || dl.Before(s.settleBy)) {
		s.settleBy = dl
	}
	s.mu.Unlock()
	s.cancel()

	done := make(chan struct{})
	go func() {
		s.jobs.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for location sync job: %w", ctx.Err())
	}
}

// startJob reserves a slot for a background job, or reports that the service is closed.
func (s *Service) startJob() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.jobs.Add(1)
	return true
}

// settleContext returns a bounded context that outlives lifecycle cancellation
// for the final-state write: at most settleTimeout, never past Close's deadline;
// false means that deadline passed and the write must be skipped.
func (s *Service) settleContext() (context.Context, context.CancelFunc, bool) {
	s.mu.Lock()
	by := s.settleBy
	s.mu.Unlock()

	deadline := time.Now().Add(settleTimeout)
	if !by.IsZero() && by.Before(deadline) {
		deadline = by
	}
	if !deadline.After(time.Now()) {
		return nil, nil, false
	}
	ctx, cancel := context.WithDeadline(context.WithoutCancel(s.baseCtx), deadline)
	return ctx, cancel, true
}

// markIfInterrupted records the interrupted state when ctx was canceled, so a
// job that never got going is not left queued.
func (s *Service) markIfInterrupted(ctx context.Context, jobID string) {
	if ctx.Err() != nil {
		s.markSyncJobInterrupted(jobID)
	}
}
