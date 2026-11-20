package media

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

// Service is what the media handlers call. The concrete service lives in
// internal/services/media; the router wires it in.
type Service interface {
	MaxFileSize() int64
	Upload(ctx context.Context, ownerUserID string, file multipart.File, header *multipart.FileHeader) (domainmedia.Media, error)
	List(ctx context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) (dtomedia.ListResult, error)
	Delete(ctx context.Context, actor domainmedia.Actor, id string) (domainmedia.Media, error)
}
