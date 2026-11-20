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
	for _, name := range []string{"r2", "cloudflare", "cloudflare-r2"} {
		t.Run(name, func(t *testing.T) {
			_, endpoint := newFakeS3(t, true)
			cfg := newConfig(endpoint)
			cfg.Provider = name
			provider, err := NewStorageProvider(cfg)
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if _, ok := provider.(*R2Adapter); !ok {
				t.Fatalf("expected R2 adapter, got %T", provider)
			}
		})
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
	_, endpoint := newFakeS3(t, true)
	cfg := newConfig(endpoint)
	cfg.Provider, cfg.BaseURL = "r2", ""
	provider, err := NewStorageProvider(cfg)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	r2, ok := provider.(*R2Adapter)
	if !ok {
		t.Fatalf("expected R2 adapter, got %T", provider)
	}
	if r2.baseURL != "https://bucket.r2.dev" {
		t.Fatalf("unexpected r2 default base URL: %q", r2.baseURL)
	}
}

func TestR2EndpointUsesTheAccountHost(t *testing.T) {
	cases := []struct{ name, endpoint, account, want string }{
		{"scheme dropped", "https://x.r2.cloudflarestorage.com", "", "x.r2.cloudflarestorage.com"},
		{"account fills a custom endpoint", "custom-endpoint", "acct", "acct.r2.cloudflarestorage.com"},
		{"an r2 endpoint is kept", "other.r2.cloudflarestorage.com", "acct", "other.r2.cloudflarestorage.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := r2Endpoint(Config{Endpoint: c.endpoint, AccountID: c.account}); got != c.want {
				t.Fatalf("r2Endpoint = %q, want %q", got, c.want)
			}
		})
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
