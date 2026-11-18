package storage

import (
	"fmt"

	"github.com/zazhedho/logus"

	"starter-kit/internal/config"
)

// InitStorage starts the storage provider (MinIO or R2) from explicit settings.
func InitStorage(cfg config.Storage) (Provider, error) {
	logus.WriteLog(logus.LogLevelDebug, "InitStorage; Initializing storage provider...")

	provider, err := NewStorageProvider(Config{
		Provider:        cfg.Provider,
		Endpoint:        cfg.Endpoint,
		AccessKeyID:     cfg.AccessKey,
		SecretAccessKey: cfg.SecretKey,
		BucketName:      cfg.Bucket,
		UseSSL:          cfg.UseSSL,
		BaseURL:         cfg.BaseURL,
		Region:          cfg.Region,
		AccountID:       cfg.R2AccountID,
	})
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("InitStorage; Failed to initialize storage provider: %s", err.Error()))
		return nil, fmt.Errorf("failed to initialize storage provider: %w", err)
	}

	logus.WriteLog(logus.LogLevelInfo, fmt.Sprintf("InitStorage; Storage provider initialized successfully. Provider: %s, Endpoint: %s, Bucket: %s",
		cfg.Provider, cfg.Endpoint, cfg.Bucket))

	return provider, nil
}
