package location

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned by repositories when a requested location record
// does not exist. Callers match it with errors.Is and never see the ORM error.
var ErrNotFound = errors.New("location record not found")

// ErrSyncJobNotFound is returned for an unknown sync job id; it also matches ErrNotFound.
var ErrSyncJobNotFound = fmt.Errorf("location sync job not found: %w", ErrNotFound)

var (
	// ErrInvalidCode is matched (errors.Is) by every location code that fails
	// validation. Build instances with NewInvalidCode.
	ErrInvalidCode = errors.New("invalid location code")

	// ErrUpstream is returned when the Location Service cannot supply data: it
	// is unreachable, answers with an error status, or sends an unusable body.
	ErrUpstream = errors.New("location service unavailable")

	// ErrShuttingDown is returned when background work is requested after
	// shutdown has begun.
	ErrShuttingDown = errors.New("location service is shutting down")

	// ErrSyncRunning is returned when a location sync is requested while
	// another one is queued or running.
	ErrSyncRunning = errors.New("location sync is already running")

	// ErrInvalidSync is matched (errors.Is) by every sync request validation
	// failure. Build instances with NewInvalidSync.
	ErrInvalidSync = errors.New("invalid location sync request")
)

type invalidSyncError struct{ msg string }

func (e *invalidSyncError) Error() string { return e.msg }

func (e *invalidSyncError) Unwrap() error { return ErrInvalidSync }

// NewInvalidSync returns a validation error whose Error text is msg and which
// matches ErrInvalidSync.
func NewInvalidSync(msg string) error { return &invalidSyncError{msg: msg} }

type invalidCodeError struct{ field string }

func (e *invalidCodeError) Error() string { return e.field + " must be 1 to 20 digits" }

func (e *invalidCodeError) Unwrap() error { return ErrInvalidCode }

// NewInvalidCode returns a validation error naming the request field whose
// value is not a location code.
func NewInvalidCode(field string) error { return &invalidCodeError{field: field} }
