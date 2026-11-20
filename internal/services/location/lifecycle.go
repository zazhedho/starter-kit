package location

import (
	"context"
	"fmt"
	"time"

	"github.com/zazhedho/logus"
)

const (
	staleMessage    = "The service instance running this location sync stopped before it completed."
	shutdownMessage = "Application shut down before the location sync completed."

	settleTimeout = 10 * time.Second
)

func (s *Service) RecoverInterruptedJobs(ctx context.Context) error {
	if err := s.repo.FailStaleSyncJobs(ctx, s.staleAfter, time.Now(), staleMessage); err != nil {
		return fmt.Errorf("mark interrupted location sync jobs: %w", err)
	}
	return nil
}

func (s *Service) Interrupt() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
}

func (s *Service) interrupted() bool {
	select {
	case <-s.stopped:
		return true
	default:
		return false
	}
}

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

func (s *Service) startJob() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.jobs.Add(1)
	return true
}

// Outlives lifecycle cancellation for the final write: at most settleTimeout, never past Close's deadline.
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
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	return ctx, cancel, true
}

func (s *Service) settle(jobID string, write func(ctx context.Context) error, what string) {
	ctx, cancel, ok := s.settleContext()
	if !ok {
		logus.Logf(logus.LevelWarn, "location: sync job %s: shutdown deadline passed before it was %s; its state is not recorded", jobID, what)
		return
	}
	defer cancel()
	if err := write(ctx); err != nil {
		logus.Logf(logus.LevelError, "location: failed to record sync job %s as %s: %v", jobID, what, err)
	}
}
