package storage

import (
	"fmt"

	"github.com/zazhedho/gokit"
)

// NewStorageProvider returns the adapter named by config.Provider (minio, or
// r2 / cloudflare / cloudflare-r2) and an error for any other name.
func NewStorageProvider(config Config) (Provider, error) {
	provider := gokit.NormalizeKey(config.Provider)

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
