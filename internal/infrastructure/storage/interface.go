package storage

import (
	"context"
	"mime/multipart"
)

// StoredFile describes an object a provider has written.
type StoredFile struct {
	ObjectName string
	URL        string
}

// Provider is the object storage the application uses. The media service
// depends on the same two methods through its own port.
type Provider interface {
	// UploadFile stores a multipart file under folder; the object name is generated.
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (StoredFile, error)

	// DeleteObject removes the object stored under objectName (StoredFile.ObjectName).
	DeleteObject(ctx context.Context, objectName string) error
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
	Region          string // R2 needs "auto"; empty lets MinIO use its own region
	AccountID       string // For R2
	PublicRead      bool   // MinIO: give a bucket this service creates an anonymous read policy
}
