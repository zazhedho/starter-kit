package storage

import (
	"context"
	"fmt"
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
}

// NewR2Adapter connects to R2 and creates the bucket when it is missing. Without
// BaseURL, files are addressed under https://<bucket>.r2.dev. Public access to R2
// is configured in Cloudflare, not through a bucket policy.
func NewR2Adapter(config Config) (*R2Adapter, error) {
	endpoint := r2Endpoint(config)

	r2Client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
		Region: config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create R2 client: %w", err)
	}

	if _, err := ensureBucket(r2Client, config.BucketName, config.Region); err != nil {
		return nil, err
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://%s.r2.dev", config.BucketName)
	}

	return &R2Adapter{
		client:     r2Client,
		bucketName: config.BucketName,
		baseURL:    baseURL,
	}, nil
}

// r2Endpoint is the host to dial: the account's own R2 host when an account ID
// is set and the endpoint is not already one, else the endpoint without scheme.
func r2Endpoint(config Config) string {
	endpoint := strings.TrimPrefix(config.Endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	if config.AccountID != "" && !strings.Contains(endpoint, ".r2.cloudflarestorage.com") {
		endpoint = fmt.Sprintf("%s.r2.cloudflarestorage.com", config.AccountID)
	}
	return endpoint
}

func (r *R2Adapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (StoredFile, error) {
	objectName, err := uploadMultipart(ctx, r.client, r.bucketName, file, fileHeader, folder, "failed to upload file to R2")
	if err != nil {
		return StoredFile{}, err
	}
	return StoredFile{ObjectName: objectName, URL: fmt.Sprintf("%s/%s", strings.TrimRight(r.baseURL, "/"), objectName)}, nil
}

func (r *R2Adapter) DeleteObject(ctx context.Context, objectName string) error {
	if err := r.client.RemoveObject(ctx, r.bucketName, objectName, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete file from R2: %w", err)
	}
	return nil
}
