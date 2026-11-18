package handlermedia

import (
	"context"
	"mime/multipart"

	"github.com/zazhedho/authkit"

	domainmedia "starter-kit/internal/domain/media"
)

// Service is what the media handlers call. The concrete service lives in
// internal/services/media; the router wires it in.
type Service interface {
	MaxFileSize() int64
	Upload(ctx context.Context, ownerUserID string, file multipart.File, header *multipart.FileHeader) (domainmedia.Media, error)
	Delete(ctx context.Context, scope authkit.Scope, id string) (domainmedia.Media, error)
}
