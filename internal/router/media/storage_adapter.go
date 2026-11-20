package media

import (
	"context"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
	"starter-kit/internal/infrastructure/storage"
	servicemedia "starter-kit/internal/services/media"
)

// storageAdapter lets a storage.Provider satisfy the media service's port: the
// provider reports its own StoredFile and the service wants the domain one.
type storageAdapter struct{ provider storage.Provider }

var _ servicemedia.Storage = storageAdapter{}

func (a storageAdapter) UploadFile(ctx context.Context, file multipart.File, header *multipart.FileHeader, folder string) (domainmedia.StoredFile, error) {
	stored, err := a.provider.UploadFile(ctx, file, header, folder)
	if err != nil {
		return domainmedia.StoredFile{}, err
	}
	return domainmedia.StoredFile{ObjectName: stored.ObjectName, URL: stored.URL}, nil
}

func (a storageAdapter) DeleteObject(ctx context.Context, objectName string) error {
	return a.provider.DeleteObject(ctx, objectName)
}
