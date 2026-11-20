package storage

import (
	"context"
	"fmt"
	"mime/multipart"
	"strings"
)

type R2Adapter struct {
	s3Core
	baseURL string
}

// NewR2Adapter sets no bucket policy: public access to R2 is configured in Cloudflare.
func NewR2Adapter(config Config) (*R2Adapter, error) {
	core, err := newS3Core("R2", config, r2Endpoint(config))
	if err != nil {
		return nil, err
	}

	if _, err := ensureBucket(core.client, config.BucketName, config.Region); err != nil {
		return nil, err
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://%s.r2.dev", config.BucketName)
	}

	return &R2Adapter{s3Core: core, baseURL: baseURL}, nil
}

func r2Endpoint(config Config) string {
	endpoint := strings.TrimPrefix(config.Endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	if config.AccountID != "" && !strings.Contains(endpoint, ".r2.cloudflarestorage.com") {
		endpoint = fmt.Sprintf("%s.r2.cloudflarestorage.com", config.AccountID)
	}
	return endpoint
}

func (r *R2Adapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (string, string, error) {
	objectName, err := r.upload(ctx, file, fileHeader, folder)
	if err != nil {
		return "", "", err
	}
	return objectName, fmt.Sprintf("%s/%s", strings.TrimRight(r.baseURL, "/"), objectName), nil
}
