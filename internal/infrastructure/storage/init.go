package storage

import (
	"fmt"

	"github.com/zazhedho/logus"

	"starter-kit/internal/config"
)

func InitStorage(cfg config.Storage) (Provider, error) {
	logus.Log(logus.LevelDebug, "InitStorage; Initializing storage provider...")

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
		PublicRead:      cfg.PublicRead,
	})
	if err != nil {
		logus.Logf(logus.LevelError, "InitStorage; Failed to initialize storage provider: %s", err.Error())
		return nil, fmt.Errorf("failed to initialize storage provider: %w", err)
	}

	logus.Logf(logus.LevelInfo, "InitStorage; Storage provider initialized successfully. Provider: %s, Endpoint: %s, Bucket: %s",
		cfg.Provider, cfg.Endpoint, cfg.Bucket)

	return provider, nil
}
