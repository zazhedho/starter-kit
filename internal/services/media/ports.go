package servicemedia

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
)

// Storage is the object storage the media service needs. Adapters live in
// internal/infrastructure/storage and satisfy it by method set.
type Storage interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (domainmedia.StoredFile, error)
	DeleteFile(ctx context.Context, fileURL string) error
}
