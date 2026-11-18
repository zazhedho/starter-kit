package media

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	domainmedia "starter-kit/internal/domain/media"
)

const (
	defaultMaxFileSize = int64(10 << 20)
	mediaFolder        = "media"
)

var defaultContentTypes = []string{
	"application/pdf",
	"image/gif",
	"image/jpeg",
	"image/png",
	"image/webp",
}

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
	if media.OwnerUserID != strings.TrimSpace(actor.UserID) && !actor.IsSuperAdmin {
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

// newUUIDv7 returns a time-ordered UUID, falling back to a random one if the
// clock source fails. The router normally injects the same behavior.
func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

func detectContentType(file multipart.File) (string, error) {
	buffer := make([]byte, 512)
	n, err := io.ReadFull(file, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	if n == 0 {
		return "", domainmedia.ErrEmptyFile
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	return normalizeContentType(http.DetectContentType(buffer[:n])), nil
}

func normalizeContentType(contentType string) string {
	contentType, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(contentType)
}

func extensionForContentType(contentType string) string {
	switch contentType {
	case "application/pdf":
		return ".pdf"
	case "image/gif":
		return ".gif"
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
}

func safeFilename(filename string) string {
	return path.Base(strings.ReplaceAll(strings.TrimSpace(filename), "\\", "/"))
}
