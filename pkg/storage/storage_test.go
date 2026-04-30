package storage

import (
	"context"
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

func TestBuildObjectNameKeepsExtensionAndTrimsFolder(t *testing.T) {
	got := buildObjectName("avatar.png", "/users/")
	if !strings.HasPrefix(got, "users/") {
		t.Fatalf("expected folder prefix, got %q", got)
	}
	if !strings.HasSuffix(got, ".png") {
		t.Fatalf("expected extension to be preserved, got %q", got)
	}
}

func TestExtractObjectNameFromProviderURLs(t *testing.T) {
	minio := &MinIOAdapter{bucketName: "uploads", baseURL: "http://localhost:9000"}
	if got := minio.extractObjectName("http://localhost:9000/uploads/users/avatar.png"); got != "users/avatar.png" {
		t.Fatalf("unexpected minio object name: %q", got)
	}
	if got := minio.GetFileURL("users/avatar.png"); got != "http://localhost:9000/uploads/users/avatar.png" {
		t.Fatalf("unexpected minio file url: %q", got)
	}
	if got := minio.extractObjectName("avatar.png"); got != "" {
		t.Fatalf("expected empty object name for short url, got %q", got)
	}
	if got := minio.extractObjectName("http://localhost:9000/uploads"); got != "" {
		t.Fatalf("expected empty object name for bucket-only url, got %q", got)
	}
	if err := minio.DeleteFile(context.Background(), "http://localhost:9000/no-bucket/avatar.png"); err == nil {
		t.Fatal("expected invalid minio url error")
	}

	r2 := &R2Adapter{baseURL: "https://cdn.example.com"}
	if got := r2.extractObjectName("https://cdn.example.com/users/avatar.png"); got != "users/avatar.png" {
		t.Fatalf("unexpected r2 object name: %q", got)
	}
	if got := r2.extractObjectName("https://pub.example.com/users/avatar.png"); got != "users/avatar.png" {
		t.Fatalf("unexpected r2 fallback object name: %q", got)
	}
	if got := r2.extractObjectName("avatar.png"); got != "avatar.png" {
		t.Fatalf("expected bare r2 object name, got %q", got)
	}
	if got := r2.GetFileURL("users/avatar.png"); got != "https://cdn.example.com/users/avatar.png" {
		t.Fatalf("unexpected r2 file url: %q", got)
	}
	if err := r2.DeleteFile(context.Background(), ""); err == nil {
		t.Fatal("expected invalid r2 url error")
	}
}
