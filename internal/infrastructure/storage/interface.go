package storage

import (
	"context"
	"mime/multipart"
)

type Provider interface {
	UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (objectName, url string, err error)

	DeleteObject(ctx context.Context, objectName string) error
}

type Config struct {
	Provider        string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	UseSSL          bool
	BaseURL         string
	Region          string
	AccountID       string
	PublicRead      bool
}
