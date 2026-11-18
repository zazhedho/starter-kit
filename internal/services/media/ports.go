package servicemedia

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
)

// Repository is the persistence the media service needs. The adapter in
// internal/repositories/media satisfies it by method set and returns
// domainmedia.ErrNotFound for a missing row.
type Repository interface {
	Store(ctx context.Context, media domainmedia.Media) error
	GetByID(ctx context.Context, id string) (domainmedia.Media, error)
	Delete(ctx context.Context, id string) error
}

// Storage is the object storage the media service needs. Adapters live in
// internal/infrastructure/storage and satisfy it by method set.
type Storage interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (domainmedia.StoredFile, error)
	DeleteFile(ctx context.Context, fileURL string) error
}
