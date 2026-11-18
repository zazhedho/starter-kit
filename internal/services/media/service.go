package media

import (
	"context"
	"errors"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

const (
	defaultMaxFileSize = int64(10 << 20)
	mediaFolder        = "media"
)

// Options tunes the service. The zero value is valid: a 10 MiB limit, the
// default content types and UUIDv7 identifiers.
type Options struct {
	// MaxFileSize is the largest accepted upload in bytes; zero or less means 10 MiB.
	MaxFileSize int64
	// AllowedContentTypes lists accepted media types; empty means the defaults.
	AllowedContentTypes []string
	// NewID returns a new identifier for a stored media row; nil means UUIDv7.
	NewID func() string
}

type Service struct {
	repo                Repository
	storage             Storage
	newID               func() string
	maxFileSize         int64
	allowedContentTypes map[string]struct{}
}

func NewService(repo Repository, storage Storage, opts Options) *Service {
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = defaultMaxFileSize
	}
	allowedContentTypes := opts.AllowedContentTypes
	if len(allowedContentTypes) == 0 {
		allowedContentTypes = defaultContentTypes
	}
	newID := opts.NewID
	if newID == nil {
		newID = newUUIDv7
	}

	allowed := make(map[string]struct{}, len(allowedContentTypes))
	for _, contentType := range allowedContentTypes {
		if normalized := normalizeContentType(contentType); normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}

	return &Service{
		repo:                repo,
		storage:             storage,
		newID:               newID,
		maxFileSize:         maxFileSize,
		allowedContentTypes: allowed,
	}
}

func (s *Service) MaxFileSize() int64 {
	return s.maxFileSize
}

func (s *Service) Upload(ctx context.Context, ownerUserID string, file multipart.File, header *multipart.FileHeader) (domainmedia.Media, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if _, err := uuid.Parse(ownerUserID); err != nil {
		return domainmedia.Media{}, domainmedia.ErrMediaForbidden
	}
	if file == nil || header == nil || header.Size <= 0 {
		return domainmedia.Media{}, domainmedia.ErrEmptyFile
	}
	if header.Size > s.maxFileSize {
		return domainmedia.Media{}, domainmedia.ErrFileTooLarge
	}

	contentType, err := detectContentType(file)
	if err != nil {
		return domainmedia.Media{}, err
	}
	if _, ok := s.allowedContentTypes[contentType]; !ok {
		return domainmedia.Media{}, domainmedia.ErrUnsupportedContentType
	}

	uploadHeader := *header
	uploadHeader.Header = make(textproto.MIMEHeader)
	uploadHeader.Header.Set("Content-Type", contentType)
	uploadHeader.Filename = "upload" + extensionForContentType(contentType)

	uploaded, err := s.storage.UploadFile(ctx, file, &uploadHeader, mediaFolder)
	if err != nil {
		return domainmedia.Media{}, err
	}

	media := domainmedia.Media{
		ID:           s.newID(),
		OwnerUserID:  ownerUserID,
		ObjectKey:    uploaded.ObjectName,
		URL:          uploaded.URL,
		OriginalName: safeFilename(header.Filename),
		ContentType:  contentType,
		Size:         header.Size,
		CreatedAt:    time.Now(),
	}
	if err := s.repo.Store(ctx, media); err != nil {
		cleanupErr := s.storage.DeleteFile(ctx, uploaded.URL)
		return domainmedia.Media{}, errors.Join(err, cleanupErr)
	}

	return media, nil
}

func (s *Service) Delete(ctx context.Context, actor domainmedia.Actor, id string) (domainmedia.Media, error) {
	media, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return domainmedia.Media{}, err
	}
	if media.OwnerUserID != strings.TrimSpace(actor.UserID) && !actor.CanDeleteAny {
		return domainmedia.Media{}, domainmedia.ErrMediaForbidden
	}

	if err := s.storage.DeleteFile(ctx, media.URL); err != nil {
		return domainmedia.Media{}, err
	}
	if err := s.repo.Delete(ctx, media.ID); err != nil {
		return domainmedia.Media{}, err
	}

	return media, nil
}

// List returns a page of media and the total match count. Without list_any the
// owner filter is forced to the caller, whatever the request asked for.
func (s *Service) List(ctx context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error) {
	if !actor.CanListAny {
		req.OwnerUserID = strings.TrimSpace(actor.UserID)
	}
	return s.repo.List(ctx, req)
}

// newUUIDv7 returns a time-ordered UUID, falling back to a random one if the
// clock source fails. The router normally injects the same behavior.
func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}
