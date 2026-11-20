package location

import (
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("location record not found")

var ErrSyncJobNotFound = fmt.Errorf("location sync job not found: %w", ErrNotFound)

var (
	ErrInvalidCode = errors.New("invalid location code")

	ErrUpstream = errors.New("location service unavailable")

	ErrShuttingDown = errors.New("location service is shutting down")

	ErrSyncRunning = errors.New("location sync is already running")

	ErrInvalidSync = errors.New("invalid location sync request")
)

type invalidSyncError struct{ msg string }

func (e *invalidSyncError) Error() string { return e.msg }

func (e *invalidSyncError) Unwrap() error { return ErrInvalidSync }

func NewInvalidSync(msg string) error { return &invalidSyncError{msg: msg} }

type invalidCodeError struct{ field string }

func (e *invalidCodeError) Error() string { return e.field + " must be 1 to 20 digits" }

func (e *invalidCodeError) Unwrap() error { return ErrInvalidCode }

func NewInvalidCode(field string) error { return &invalidCodeError{field: field} }
