package media

import (
	"fmt"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"starter-kit/pkg/storage"
	"strconv"
)

// InitStorage initializes and returns a storage provider (MinIO or R2)
func InitStorage() (storage.StorageProvider, error) {
	logus.WriteLog(logus.LogLevelDebug, "InitStorage; Initializing storage provider...")

	provider := utils.NormalizeKey(utils.GetEnv("STORAGE_PROVIDER", "minio"))

	useSSL, _ := strconv.ParseBool(utils.GetEnv("STORAGE_USE_SSL", "false"))

	config := storage.Config{
		Provider:        provider,
		Endpoint:        utils.GetEnv("STORAGE_ENDPOINT", "localhost:9000"),
		AccessKeyID:     utils.GetEnv("STORAGE_ACCESS_KEY", "minioadmin"),
		SecretAccessKey: utils.GetEnv("STORAGE_SECRET_KEY", "minioadmin"),
		BucketName:      utils.GetEnv("STORAGE_BUCKET_NAME", "uploads"),
		UseSSL:          useSSL,
		BaseURL:         utils.GetEnv("STORAGE_BASE_URL", "http://localhost:9000"),
		Region:          utils.GetEnv("STORAGE_REGION", "auto"),
		AccountID:       utils.GetEnv("R2_ACCOUNT_ID", ""),
	}

	storageProvider, err := storage.NewStorageProvider(config)
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("InitStorage; Failed to initialize storage provider: %s", err.Error()))
		return nil, fmt.Errorf("failed to initialize storage provider: %w", err)
	}

	logus.WriteLog(logus.LogLevelInfo, fmt.Sprintf("InitStorage; Storage provider initialized successfully. Provider: %s, Endpoint: %s, Bucket: %s",
		provider, config.Endpoint, config.BucketName))

	return storageProvider, nil
}
