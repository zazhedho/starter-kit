package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
)

var startupTimeout = 15 * time.Second

func ensureBucket(client *minio.Client, bucket, region string) (created bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return false, fmt.Errorf("failed to check bucket existence: %w", err)
	}
	if exists {
		return false, nil
	}
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
		return false, fmt.Errorf("failed to create bucket: %w", err)
	}
	return true, nil
}
