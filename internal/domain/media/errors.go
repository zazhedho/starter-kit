package media

import "errors"

var (
	ErrEmptyFile              = errors.New("file is empty")
	ErrFileTooLarge           = errors.New("file exceeds maximum size")
	ErrUnsupportedContentType = errors.New("unsupported media content type")
	ErrMediaForbidden         = errors.New("media does not belong to current user")
	ErrNotFound               = errors.New("media not found")
)
