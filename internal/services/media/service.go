package media

import (
	"context"
	"mime/multipart"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zazhedho/logus"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

const (
	defaultMaxFileSize   = int64(10 << 20)
	mediaFolder          = "media"
	orphanCleanupTimeout = 10 * time.Second
)

type Options struct {
	MaxFileSize         int64
	AllowedContentTypes []string
	NewID               func() string
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
		allowedContentTypes = domainmedia.SupportedContentTypes()
	}
	newID := opts.NewID
	if newID == nil {
		newID = newUUIDv7
	}

	// Only types the module can store safely are allowed, whatever Options says.
	supported := domainmedia.SupportedContentTypes()
	allowed := make(map[string]struct{}, len(allowedContentTypes))
	for _, contentType := range allowedContentTypes {
		if normalized := domainmedia.NormalizeContentType(contentType); slices.Contains(supported, normalized) {
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
	uploadHeader.Filename = "upload" + domainmedia.ExtensionFor(contentType)

	objectName, url, err := s.storage.UploadFile(ctx, file, &uploadHeader, mediaFolder)
	if err != nil {
		return domainmedia.Media{}, err
	}

	media := domainmedia.Media{
		ID:           s.newID(),
		OwnerUserID:  ownerUserID,
		ObjectKey:    objectName,
		URL:          url,
		OriginalName: domainmedia.SafeFilename(header.Filename),
		ContentType:  contentType,
		Size:         header.Size,
		CreatedAt:    time.Now(),
	}
	if err := s.repo.Store(ctx, &media); err != nil {
		s.removeOrphan(ctx, objectName)
		return domainmedia.Media{}, err
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

	if err := s.storage.DeleteObject(ctx, media.ObjectKey); err != nil {
		return domainmedia.Media{}, err
	}
	if err := s.repo.Delete(ctx, media.ID); err != nil {
		return domainmedia.Media{}, err
	}

	return media, nil
}

// The request context may be canceled, so the removal gets its own short deadline.
func (s *Service) removeOrphan(ctx context.Context, objectName string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orphanCleanupTimeout)
	defer cancel()
	if err := s.storage.DeleteObject(cleanupCtx, objectName); err != nil {
		logus.Logf(logus.LevelError, "media: failed to remove orphan object %s after a failed metadata write: %v", objectName, err)
	}
}

// List forces the owner filter to the caller without list_any.
func (s *Service) List(ctx context.Context, actor domainmedia.Actor, req dtomedia.ListRequest) (dtomedia.ListResult, error) {
	if !actor.CanListAny {
		req.OwnerUserID = strings.TrimSpace(actor.UserID)
	}
	return s.repo.List(ctx, req)
}

func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}
