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
	Store(ctx context.Context, media *domainmedia.Media) error
	GetByID(ctx context.Context, id string) (domainmedia.Media, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, req dtomedia.ListRequest) (dtomedia.ListResult, error)
}

// Storage is the object storage the media service needs. The providers in
// internal/infrastructure/storage satisfy it by method set.
type Storage interface {
	// UploadFile stores the file under folder and returns the generated object
	// name and the URL of the object.
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (objectName, url string, err error)
	// DeleteObject removes an object by the name UploadFile returned.
	DeleteObject(ctx context.Context, objectName string) error
}
