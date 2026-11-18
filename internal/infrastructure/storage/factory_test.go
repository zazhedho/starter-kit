package storage

import (
	"strings"
	"testing"
)

func TestNewStorageProviderRejectsUnknownProvider(t *testing.T) {
	_, err := NewStorageProvider(Config{Provider: "local"})
	if err == nil || !strings.Contains(err.Error(), "unsupported storage provider") {
		t.Fatalf("expected unsupported provider error, got %v", err)
	}
}

func TestNewStorageProviderCreatesR2AdapterAliases(t *testing.T) {
	provider, err := NewStorageProvider(Config{
		Provider:        "cloudflare-r2",
		Endpoint:        "https://example.r2.cloudflarestorage.com",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		BucketName:      "bucket",
		BaseURL:         "https://cdn.example.com",
		UseSSL:          true,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if _, ok := provider.(*R2Adapter); !ok {
		t.Fatalf("expected R2 adapter, got %T", provider)
	}
}

func TestNewStorageProviderRejectsInvalidMinIOEndpoint(t *testing.T) {
	_, err := NewStorageProvider(Config{
		Provider:        "minio",
		Endpoint:        "://bad-endpoint",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		BucketName:      "bucket",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to create MinIO client") {
		t.Fatalf("expected invalid minio endpoint error, got %v", err)
	}
}

func TestNewStorageProviderCreatesR2AdapterWithDefaults(t *testing.T) {
	provider, err := NewStorageProvider(Config{
		Provider:        "r2",
		Endpoint:        "custom-endpoint",
		AccountID:       "account-1",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		BucketName:      "bucket",
		UseSSL:          true,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	r2, ok := provider.(*R2Adapter)
	if !ok {
		t.Fatalf("expected R2 adapter, got %T", provider)
	}
	if r2.baseURL != "https://bucket.r2.dev" || r2.accountID != "account-1" {
		t.Fatalf("unexpected r2 defaults: %+v", r2)
	}
}

func TestNewStorageProviderReturnsNilInterfaceOnError(t *testing.T) {
	provider, err := NewStorageProvider(Config{
		Provider:        "minio",
		Endpoint:        "://bad-endpoint",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
		BucketName:      "bucket",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if provider != nil {
		t.Fatalf("expected a nil Provider on error, got %#v", provider)
	}
}
