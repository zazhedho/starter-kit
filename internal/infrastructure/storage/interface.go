package storage

import (
	"context"
	"io"
	"mime/multipart"
)

// StoredFile describes an object a provider has written.
type StoredFile struct {
	ObjectName string
	URL        string
}

// Provider is the full set of storage operations; the media service depends only
// on the two-method servicemedia.Storage port it satisfies.
type Provider interface {
	// UploadFile stores a multipart file under folder; the object name is generated.
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (StoredFile, error)

	// UploadFileFromBytes is UploadFile for in-memory data; an empty contentType
	// is stored as application/octet-stream.
	UploadFileFromBytes(ctx context.Context, data []byte, filename string, folder string, contentType string) (StoredFile, error)

	// DeleteFile takes the URL the upload returned, not the object name.
	DeleteFile(ctx context.Context, fileURL string) error

	GetFileURL(objectName string) string

	// DownloadFile takes the object name; the caller must close the reader.
	DownloadFile(ctx context.Context, objectName string) (io.ReadCloser, error)
}

// Config selects and configures a storage provider.
type Config struct {
	Provider        string // "minio" or "r2"
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	UseSSL          bool
	BaseURL         string // Public URL to access files
	Region          string // For R2
	AccountID       string // For R2
}
