package storage

import (
	"context"
	"fmt"
	"mime/multipart"
	"strings"
)

// R2Adapter is the Cloudflare R2 implementation of Provider. Files are
// addressed under <baseURL>/<object>.
type R2Adapter struct {
	s3Core
	baseURL string
}

// NewR2Adapter connects to R2 and creates the bucket when it is missing. Without
// BaseURL, files are addressed under https://<bucket>.r2.dev. Public access to R2
// is configured in Cloudflare, not through a bucket policy.
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

func (r *R2Adapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (string, string, error) {
	objectName, err := r.upload(ctx, file, fileHeader, folder)
	if err != nil {
		return "", "", err
	}
	return objectName, fmt.Sprintf("%s/%s", strings.TrimRight(r.baseURL, "/"), objectName), nil
}
