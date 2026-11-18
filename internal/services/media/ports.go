package media

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

// Repository is the persistence the service needs; the adapter satisfies it and
// returns domainmedia.ErrNotFound for a missing row.
type Repository interface {
	Store(ctx context.Context, media domainmedia.Media) error
	GetByID(ctx context.Context, id string) (domainmedia.Media, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error)
}

// Storage is the object storage the media service needs. Adapters live in
// internal/infrastructure/storage and satisfy it by method set.
type Storage interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (domainmedia.StoredFile, error)
	DeleteFile(ctx context.Context, fileURL string) error
}
