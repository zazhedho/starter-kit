package media

import domainmedia "starter-kit/internal/domain/media"

type ListRequest struct {
	Search         string
	OwnerUserID    string
	ContentType    string
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
}

type ListResult struct {
	Items []domainmedia.Media
	Total int64
	Limit int
}
