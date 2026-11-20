package storage

import (
	"context"
	"fmt"
	"mime/multipart"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// s3Core is what MinIO and R2 share: both speak the S3 API through the same
// client. An adapter embeds it and adds only its URL layout.
type s3Core struct {
	client *minio.Client
	bucket string
	label  string // provider name in error messages
}

func newS3Core(label string, config Config, endpoint string) (s3Core, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
		Region: config.Region,
	})
	if err != nil {
		return s3Core{}, fmt.Errorf("failed to create %s client: %w", label, err)
	}
	return s3Core{client: client, bucket: config.BucketName, label: label}, nil
}

// upload stores the file under a generated object name and returns the name.
func (c s3Core) upload(ctx context.Context, file multipart.File, header *multipart.FileHeader, folder string) (string, error) {
	objectName := buildObjectName(header.Filename, folder)
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if _, err := c.client.PutObject(ctx, c.bucket, objectName, file, header.Size, minio.PutObjectOptions{ContentType: contentType}); err != nil {
		return "", fmt.Errorf("failed to upload file to %s: %w", c.label, err)
	}
	return objectName, nil
}

// DeleteObject removes the object stored under objectName.
func (c s3Core) DeleteObject(ctx context.Context, objectName string) error {
	if err := c.client.RemoveObject(ctx, c.bucket, objectName, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete file from %s: %w", c.label, err)
	}
	return nil
}
