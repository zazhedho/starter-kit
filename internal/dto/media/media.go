// Package media holds the media module's request shapes. It keeps the list
// parameters free of any transport or query-library type.
package media

import domainmedia "starter-kit/internal/domain/media"

// ListRequest is a media list query. OwnerUserID and ContentType are exact-match
// filters; Search matches the original file name.
type ListRequest struct {
	Search         string
	OwnerUserID    string
	ContentType    string
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
}

// ListResult is one page of media. Limit is the page size the repository
// applied, which can differ from the requested one; use it for pagination
// metadata.
type ListResult struct {
	Items []domainmedia.Media
	Total int64
	Limit int
}
