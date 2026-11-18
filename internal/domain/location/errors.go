package domainlocation

import "errors"

// ErrNotFound is returned by repositories when a requested location record
// does not exist. Callers match it with errors.Is and never see the ORM error.
var ErrNotFound = errors.New("location record not found")
