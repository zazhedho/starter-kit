package location

import (
	"context"
	"fmt"
	"time"

	"github.com/zazhedho/logus"
)

// Messages recorded on jobs that did not complete. Both leave the job failed
// with the message "Location sync interrupted".
const (
	staleMessage    = "The service instance running this location sync stopped before it completed."
	shutdownMessage = "Application shut down before the location sync completed."

	// settleTimeout bounds the final database write of a canceled job, which
	// must not use the canceled context.
	settleTimeout = 10 * time.Second
)

// RecoverInterruptedJobs fails every queued or running job whose heartbeat is
// stale: the instance that owned it is gone. A job of an instance that is still
// alive, for example during a rolling deploy, is left alone. Call it once at startup.
func (s *Service) RecoverInterruptedJobs(ctx context.Context) error {
	if err := s.repo.FailStaleSyncJobs(ctx, s.staleAfter, time.Now(), staleMessage); err != nil {
		return fmt.Errorf("mark interrupted location sync jobs: %w", err)
	}
	return nil
}

// Interrupt cancels the running sync job and refuses new ones, without waiting.
// The job then records its final state while the rest of the shutdown goes on.
func (s *Service) Interrupt() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
}

// Close interrupts the sync job and waits until ctx ends or the job returns.
// The job's final write is bounded by ctx's deadline and settleTimeout.
// Safe to call twice; afterwards StartSync fails with ErrShuttingDown.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if dl, ok := ctx.Deadline(); ok && (s.settleBy.IsZero() || dl.Before(s.settleBy)) {
		s.settleBy = dl
	}
	s.mu.Unlock()
	s.Interrupt()

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

// settle records the final state of a job under settleContext; it logs and
// returns when the shutdown deadline has passed or the job no longer belongs
// to this instance.
func (s *Service) settle(jobID string, write func(ctx context.Context) error, what string) {
	ctx, cancel, ok := s.settleContext()
	if !ok {
		logus.Logf(logus.LevelWarn, "location sync job %s: shutdown deadline passed before it was %s; its state is not recorded", jobID, what)
		return
	}
	defer cancel()
	if err := write(ctx); err != nil {
		logus.Logf(logus.LevelError, "failed to record location sync job %s as %s: %v", jobID, what, err)
	}
}
