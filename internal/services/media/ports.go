package media

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

type Repository interface {
	Store(ctx context.Context, media *domainmedia.Media) error
	GetByID(ctx context.Context, id string) (domainmedia.Media, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, req dtomedia.ListRequest) (dtomedia.ListResult, error)
}

type Storage interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (objectName, url string, err error)
	DeleteObject(ctx context.Context, objectName string) error
}
