package storage

import (
	"context"
	"mime/multipart"
)

// Provider is the object storage the application uses. The media service
// declares the same two methods as its own port, so a Provider satisfies it.
type Provider interface {
	// UploadFile stores a multipart file under folder and returns the generated
	// object name and the URL of the object.
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (objectName, url string, err error)

	// DeleteObject removes the object stored under the name UploadFile returned.
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
