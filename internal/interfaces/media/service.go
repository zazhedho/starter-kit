package interfacemedia

import (
	"context"
	"github.com/zazhedho/authkit"
	"mime/multipart"

	domainmedia "starter-kit/internal/domain/media"
)

type ServiceMediaInterface interface {
	MaxFileSize() int64
	Upload(ctx context.Context, ownerUserID string, file multipart.File, header *multipart.FileHeader) (domainmedia.Media, error)
	Delete(ctx context.Context, scope authkit.Scope, id string) (domainmedia.Media, error)
}
