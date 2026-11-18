package domainlocation

import "errors"

// ErrNotFound is returned by repositories when a requested location record
// does not exist. Callers match it with errors.Is and never see the ORM error.
var ErrNotFound = errors.New("location record not found")

var (
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
