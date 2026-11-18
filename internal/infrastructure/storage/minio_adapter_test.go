package storage

import (
	"strings"
	"testing"
)

func TestNewMinIOAdapterRejectsInvalidEndpoint(t *testing.T) {
	_, err := NewMinIOAdapter(Config{
		Endpoint:        "://bad-endpoint",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		BucketName:      "bucket",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to create MinIO client") {
		t.Fatalf("expected invalid endpoint error, got %v", err)
	}
}
