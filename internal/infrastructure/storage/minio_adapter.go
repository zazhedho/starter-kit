package storage

import (
	"context"
	"fmt"
	"mime/multipart"

	"github.com/minio/minio-go/v7"
)

type MinIOAdapter struct {
	s3Core
	baseURL string
}

func NewMinIOAdapter(config Config) (*MinIOAdapter, error) {
	core, err := newS3Core("MinIO", config, config.Endpoint)
	if err != nil {
		return nil, err
	}

	created, err := ensureBucket(core.client, config.BucketName, config.Region)
	if err != nil {
		return nil, err
	}
	if created && config.PublicRead {
		if err := setPublicReadPolicy(core.client, config.BucketName); err != nil {
			return nil, err
		}
	}

	return &MinIOAdapter{s3Core: core, baseURL: config.BaseURL}, nil
}

func (m *MinIOAdapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (string, string, error) {
	objectName, err := m.upload(ctx, file, fileHeader, folder)
	if err != nil {
		return "", "", err
	}
	return objectName, fmt.Sprintf("%s/%s/%s", m.baseURL, m.bucket, objectName), nil
}

func setPublicReadPolicy(client *minio.Client, bucket string) error {
	policy := fmt.Sprintf(`{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": ["*"]},
		"Action": ["s3:GetObject"],
		"Resource": ["arn:aws:s3:::%s/*"]
	}]
}`, bucket)
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	if err := client.SetBucketPolicy(ctx, bucket, policy); err != nil {
		return fmt.Errorf("failed to set bucket policy: %w", err)
	}
	return nil
}
