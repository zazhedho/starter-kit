// Package media holds the media module's request shapes. It keeps the list
// parameters free of any transport or query-library type.
package media

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
	Offset         int
}
