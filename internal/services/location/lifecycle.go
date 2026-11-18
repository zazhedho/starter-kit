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

// Messages recorded on a job that did not run to completion. Both end in the
// state FailActiveSyncJobs leaves behind: status failed, message "Location sync
// interrupted".
const (
	restartedMessage = "Service restarted before the previous location sync completed."
	shutdownMessage  = "Application shut down before the location sync completed."

	// settleTimeout bounds the final database write of a canceled job, which
	// must not use the canceled context.
	settleTimeout = 10 * time.Second
)

// RecoverInterruptedJobs marks every queued or running sync job as failed. Call
// it once when the process starts: such a job belongs to a process that no
// longer exists.
func (s *Service) RecoverInterruptedJobs(ctx context.Context) error {
	if err := s.repo.FailActiveSyncJobs(ctx, restartedMessage); err != nil {
		return fmt.Errorf("mark interrupted location sync jobs: %w", err)
	}
	return nil
}

// Close cancels the running sync job, if any, and waits for it until ctx ends
// or the job returns. The job's final write is bounded by ctx's deadline (when
// it has one) and by settleTimeout, and is skipped once that deadline has
// passed. It is safe to call more than once; after the first call StartSync
// fails with ErrClosed.
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

// settleContext returns a bounded context that survives cancellation of the
// lifecycle context, for the writes that record a job's final state. It lasts
// settleTimeout at most, and never past the deadline Close was given; when that
// deadline has passed it reports false and the write must be skipped.
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
