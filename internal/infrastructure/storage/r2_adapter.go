package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// R2Adapter is the Cloudflare R2 implementation of Provider.
type R2Adapter struct {
	client     *minio.Client
	bucketName string
	baseURL    string
	accountID  string
}

// NewR2Adapter connects to R2. Without BaseURL, files are addressed under
// https://<bucket>.r2.dev.
func NewR2Adapter(config Config) (*R2Adapter, error) {
	endpoint := config.Endpoint

	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	if config.AccountID != "" && !strings.Contains(endpoint, ".r2.cloudflarestorage.com") {
		endpoint = fmt.Sprintf("%s.r2.cloudflarestorage.com", config.AccountID)
	}

	r2Client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create R2 client: %w", err)
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://%s.r2.dev", config.BucketName)
	}

	return &R2Adapter{
		client:     r2Client,
		bucketName: config.BucketName,
		baseURL:    baseURL,
		accountID:  config.AccountID,
	}, nil
}

func (r *R2Adapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (StoredFile, error) {
	objectName, err := uploadMultipart(ctx, r.client, r.bucketName, file, fileHeader, folder, "failed to upload file to R2")
	if err != nil {
		return StoredFile{}, err
	}
	return StoredFile{ObjectName: objectName, URL: r.GetFileURL(objectName)}, nil
}

func (r *R2Adapter) UploadFileFromBytes(ctx context.Context, data []byte, filename string, folder string, contentType string) (StoredFile, error) {
	objectName, err := uploadBytes(ctx, r.client, r.bucketName, data, filename, folder, contentType, "failed to upload file to R2")
	if err != nil {
		return StoredFile{}, err
	}
	return StoredFile{ObjectName: objectName, URL: r.GetFileURL(objectName)}, nil
}

func (r *R2Adapter) DeleteFile(ctx context.Context, fileURL string) error {
	objectName := r.extractObjectName(fileURL)
	if objectName == "" {
		return fmt.Errorf("invalid file URL")
	}

	err := r.client.RemoveObject(ctx, r.bucketName, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete file from R2: %w", err)
	}

	return nil
}

func (r *R2Adapter) GetFileURL(objectName string) string {
	return fmt.Sprintf("%s/%s", strings.TrimRight(r.baseURL, "/"), objectName)
}

func (r *R2Adapter) DownloadFile(ctx context.Context, objectName string) (io.ReadCloser, error) {
	object, err := r.client.GetObject(ctx, r.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download file from R2: %w", err)
	}
	return object, nil
}

func (r *R2Adapter) extractObjectName(fileURL string) string {
	objectName := strings.TrimPrefix(fileURL, r.baseURL)
	objectName = strings.TrimPrefix(objectName, "/")

	if objectName == "" || objectName == fileURL {
		parts := strings.Split(fileURL, "/")
		if len(parts) >= 4 {
			objectName = strings.Join(parts[3:], "/")
		}
	}

	return objectName
}
