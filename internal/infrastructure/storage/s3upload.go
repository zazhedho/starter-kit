package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"

	"github.com/minio/minio-go/v7"
)

// Both adapters speak the S3 API through the same client, so the upload steps
// live here and each adapter only adds its own error label and URL scheme.

func putObject(ctx context.Context, client *minio.Client, bucket, objectName string, reader io.Reader, size int64, contentType, errLabel string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	_, err := client.PutObject(ctx, bucket, objectName, reader, size, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("%s: %w", errLabel, err)
	}
	return nil
}

func uploadMultipart(ctx context.Context, client *minio.Client, bucket string, file multipart.File, header *multipart.FileHeader, folder, errLabel string) (string, error) {
	objectName := buildObjectName(header.Filename, folder)
	err := putObject(ctx, client, bucket, objectName, file, header.Size, header.Header.Get("Content-Type"), errLabel)
	return objectName, err
}

func uploadBytes(ctx context.Context, client *minio.Client, bucket string, data []byte, filename, folder, contentType, errLabel string) (string, error) {
	objectName := buildObjectName(filename, folder)
	err := putObject(ctx, client, bucket, objectName, bytes.NewReader(data), int64(len(data)), contentType, errLabel)
	return objectName, err
}
