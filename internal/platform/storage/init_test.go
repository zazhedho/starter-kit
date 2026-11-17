package storage

import (
	"strings"
	"testing"

	"starter-kit/internal/config"
)

func TestInitStorageReturnsErrorForUnsupportedProvider(t *testing.T) {
	provider, err := InitStorage(config.Storage{Provider: "unsupported"})
	if err == nil {
		t.Fatalf("expected error, got provider %#v", provider)
	}
	if !strings.Contains(err.Error(), "unsupported storage provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}
