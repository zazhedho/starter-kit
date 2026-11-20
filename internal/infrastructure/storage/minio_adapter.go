package storage

import (
	"context"
	"fmt"
	"mime/multipart"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// MinIOAdapter is the MinIO implementation of Provider.
type MinIOAdapter struct {
	client     *minio.Client
	bucketName string
	baseURL    string
}

// NewMinIOAdapter connects to MinIO and creates the bucket when it is missing.
// A bucket created here is private unless Config.PublicRead is set; an existing
// bucket's policy is never changed.
func NewMinIOAdapter(config Config) (*MinIOAdapter, error) {
	minioClient, err := minio.New(config.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
		Region: config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	created, err := ensureBucket(minioClient, config.BucketName, config.Region)
	if err != nil {
		return nil, err
	}
	if created && config.PublicRead {
		if err := setPublicReadPolicy(minioClient, config.BucketName); err != nil {
			return nil, err
		}
	}

	return &MinIOAdapter{
		client:     minioClient,
		bucketName: config.BucketName,
		baseURL:    config.BaseURL,
	}, nil
}

func (m *MinIOAdapter) UploadFile(ctx context.Context, file multipart.File, fileHeader *multipart.FileHeader, folder string) (StoredFile, error) {
	objectName, err := uploadMultipart(ctx, m.client, m.bucketName, file, fileHeader, folder, "failed to upload file")
	if err != nil {
		return StoredFile{}, err
	}
	return StoredFile{ObjectName: objectName, URL: fmt.Sprintf("%s/%s/%s", m.baseURL, m.bucketName, objectName)}, nil
}

func (m *MinIOAdapter) DeleteObject(ctx context.Context, objectName string) error {
	if err := m.client.RemoveObject(ctx, m.bucketName, objectName, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}

// setPublicReadPolicy lets anyone read the bucket's objects without signing.
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
