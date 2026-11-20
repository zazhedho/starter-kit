package storage

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeS3 struct {
	mu           sync.Mutex
	requests     []string
	authHeaders  []string
	bucketExists bool
	hang         chan struct{}
}

func newFakeS3(t *testing.T, bucketExists bool) (*fakeS3, string) {
	t.Helper()
	f := &fakeS3{bucketExists: bucketExists}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, strings.TrimPrefix(srv.URL, "http://")
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+path)
	f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
	hang, exists := f.hang, f.bucketExists
	f.mu.Unlock()

	isBucketCall := !strings.Contains(strings.Trim(r.URL.Path, "/"), "/")
	if isBucketCall && hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}
	switch {
	case isBucketCall && r.Method == http.MethodHead:
		if exists {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case isBucketCall && r.Method == http.MethodGet && r.URL.Query().Has("location"):
		_, _ = io.WriteString(w, `<?xml version="1.0"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
	case isBucketCall && r.Method == http.MethodPut && r.URL.Query().Has("policy"):
		w.WriteHeader(http.StatusNoContent)
	case isBucketCall && r.Method == http.MethodPut:
		f.mu.Lock()
		f.bucketExists = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut:
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeS3) seen(request string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.requests, request)
}

func (f *fakeS3) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

type multipartFile struct{ *bytes.Reader }

func (multipartFile) Close() error { return nil }

func pngHeader(name string, size int64) *multipart.FileHeader {
	return &multipart.FileHeader{Filename: name, Size: size, Header: textproto.MIMEHeader{"Content-Type": {"image/png"}}}
}

func shortenStartup(t *testing.T, d time.Duration) {
	t.Helper()
	old := startupTimeout
	startupTimeout = d
	t.Cleanup(func() { startupTimeout = old })
}

func newConfig(endpoint string) Config {
	return Config{
		Endpoint: endpoint, AccessKeyID: "access", SecretAccessKey: "secret",
		BucketName: "bucket", BaseURL: "https://files.example.test", Region: "us-east-1",
	}
}

func TestMinIOCreatesAMissingBucketPrivately(t *testing.T) {
	fake, endpoint := newFakeS3(t, false)
	if _, err := NewMinIOAdapter(newConfig(endpoint)); err != nil {
		t.Fatalf("NewMinIOAdapter: %v", err)
	}
	if !fake.seen("PUT /bucket") {
		t.Fatalf("a missing bucket must be created, requests: %v", fake.all())
	}
	if fake.seen("PUT /bucket?policy=") {
		t.Fatalf("no public policy unless STORAGE_PUBLIC_READ is set, requests: %v", fake.all())
	}
}

func TestMinIOAppliesThePublicPolicyOnlyToABucketItCreates(t *testing.T) {
	cfg := func(endpoint string) Config { c := newConfig(endpoint); c.PublicRead = true; return c }

	fake, endpoint := newFakeS3(t, false)
	if _, err := NewMinIOAdapter(cfg(endpoint)); err != nil {
		t.Fatalf("NewMinIOAdapter: %v", err)
	}
	if !fake.seen("PUT /bucket?policy=") {
		t.Fatalf("PublicRead must apply the policy to a new bucket, requests: %v", fake.all())
	}

	fake, endpoint = newFakeS3(t, true)
	if _, err := NewMinIOAdapter(cfg(endpoint)); err != nil {
		t.Fatalf("NewMinIOAdapter: %v", err)
	}
	if fake.seen("PUT /bucket") || fake.seen("PUT /bucket?policy=") {
		t.Fatalf("an existing bucket must be left alone, requests: %v", fake.all())
	}
}

func TestR2CreatesAMissingBucketLikeMinIO(t *testing.T) {
	fake, endpoint := newFakeS3(t, false)
	cfg := newConfig(endpoint)
	cfg.Region = "auto"
	if _, err := NewR2Adapter(cfg); err != nil {
		t.Fatalf("NewR2Adapter: %v", err)
	}
	if !fake.seen("PUT /bucket") {
		t.Fatalf("R2 must create a missing bucket too, requests: %v", fake.all())
	}
}

func TestStartupBucketCheckIsBounded(t *testing.T) {
	shortenStartup(t, 100*time.Millisecond)
	for name, build := range map[string]func(Config) error{
		"minio": func(c Config) error { _, err := NewMinIOAdapter(c); return err },
		"r2":    func(c Config) error { _, err := NewR2Adapter(c); return err },
	} {
		t.Run(name, func(t *testing.T) {
			fake, endpoint := newFakeS3(t, true)
			fake.hang = make(chan struct{})
			t.Cleanup(func() { close(fake.hang) })

			done := make(chan error, 1)
			go func() { done <- build(newConfig(endpoint)) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a hanging storage must fail the startup check")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the startup bucket check has no timeout")
			}
		})
	}
}

func TestTheConfiguredRegionSignsTheRequests(t *testing.T) {
	for name, build := range map[string]func(Config) error{
		"minio": func(c Config) error { _, err := NewMinIOAdapter(c); return err },
		"r2":    func(c Config) error { _, err := NewR2Adapter(c); return err },
	} {
		t.Run(name, func(t *testing.T) {
			fake, endpoint := newFakeS3(t, true)
			cfg := newConfig(endpoint)
			cfg.Region = "auto"
			if err := build(cfg); err != nil {
				t.Fatalf("build: %v", err)
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.authHeaders) == 0 || !strings.Contains(fake.authHeaders[0], "/auto/s3/aws4_request") {
				t.Fatalf("requests are not signed for the configured region: %q", fake.authHeaders)
			}
		})
	}
}

func TestUploadAndDeleteObject(t *testing.T) {
	data := []byte("\x89PNG\r\n\x1a\n")
	for name, c := range map[string]struct {
		build   func(Config) (Provider, error)
		wantURL string
	}{
		"minio": {func(c Config) (Provider, error) { return NewMinIOAdapter(c) }, "https://files.example.test/bucket/media/"},
		"r2":    {func(c Config) (Provider, error) { return NewR2Adapter(c) }, "https://files.example.test/media/"},
	} {
		t.Run(name, func(t *testing.T) {
			fake, endpoint := newFakeS3(t, true)
			p, err := c.build(newConfig(endpoint))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			objectName, url, err := p.UploadFile(context.Background(), multipartFile{bytes.NewReader(data)}, pngHeader("upload.png", int64(len(data))), "media")
			if err != nil {
				t.Fatalf("UploadFile: %v", err)
			}
			if !strings.HasPrefix(url, c.wantURL) || !strings.HasSuffix(url, ".png") || !strings.HasPrefix(objectName, "media/") {
				t.Fatalf("stored %q at %q", objectName, url)
			}
			if !fake.seen("PUT /bucket/" + objectName) {
				t.Fatalf("the object was not put, requests: %v", fake.all())
			}

			if err := p.DeleteObject(context.Background(), objectName); err != nil {
				t.Fatalf("DeleteObject: %v", err)
			}
			if !fake.seen("DELETE /bucket/" + objectName) {
				t.Fatalf("the object was not deleted by its name, requests: %v", fake.all())
			}
		})
	}
}

func TestStorageCallsFailWithACanceledContext(t *testing.T) {
	data := []byte("\x89PNG\r\n\x1a\n")
	for name, c := range map[string]struct {
		build func(Config) (Provider, error)
		label string
	}{
		"minio": {func(c Config) (Provider, error) { return NewMinIOAdapter(c) }, "MinIO"},
		"r2":    {func(c Config) (Provider, error) { return NewR2Adapter(c) }, "R2"},
	} {
		t.Run(name, func(t *testing.T) {
			_, endpoint := newFakeS3(t, true)
			p, err := c.build(newConfig(endpoint))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, _, err = p.UploadFile(ctx, multipartFile{bytes.NewReader(data)}, pngHeader("upload.png", int64(len(data))), "media")
			if err == nil || !strings.Contains(err.Error(), c.label) {
				t.Fatalf("UploadFile with a canceled context = %v, want an error naming %s", err, c.label)
			}
			err = p.DeleteObject(ctx, "media/x.png")
			if err == nil || !strings.Contains(err.Error(), c.label) {
				t.Fatalf("DeleteObject with a canceled context = %v, want an error naming %s", err, c.label)
			}
		})
	}
}
