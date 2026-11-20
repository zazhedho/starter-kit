package storage

import (
	"fmt"
	"strings"
)

func NewStorageProvider(config Config) (Provider, error) {
	provider := strings.ToLower(strings.TrimSpace(config.Provider))

	switch provider {
	case "minio":
		adapter, err := NewMinIOAdapter(config)
		if err != nil {
			return nil, err
		}
		return adapter, nil
	case "r2", "cloudflare", "cloudflare-r2":
		adapter, err := NewR2Adapter(config)
		if err != nil {
			return nil, err
		}
		return adapter, nil
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s (supported: minio, r2)", config.Provider)
	}
}
