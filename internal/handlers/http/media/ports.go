package media

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

type Service interface {
	MaxFileSize() int64
	Upload(ctx context.Context, ownerUserID string, file multipart.File, header *multipart.FileHeader) (domainmedia.Media, error)
	List(ctx context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) (dtomedia.ListResult, error)
	Delete(ctx context.Context, actor domainmedia.Actor, id string) (domainmedia.Media, error)
}
