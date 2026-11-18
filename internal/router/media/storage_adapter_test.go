package media

import (
	"context"
	"errors"
	"testing"

	domainmedia "starter-kit/internal/domain/media"
	"starter-kit/internal/testutil/routertest"
)

func TestStorageAdapterConvertsTheStoredFile(t *testing.T) {
	got, err := storageAdapter{routertest.FakeStorage{}}.UploadFile(context.Background(), nil, nil, "media")
	if err != nil {
		t.Fatal(err)
	}
	want := domainmedia.StoredFile{ObjectName: "media/object.png", URL: "https://files.example.test/media/object.png"}
	if got != want {
		t.Fatalf("UploadFile = %+v, want %+v", got, want)
	}
}

func TestStorageAdapterDeleteDelegates(t *testing.T) {
	boom := errors.New("boom")
	if err := (storageAdapter{failingDelete{routertest.FakeStorage{}, boom}}).DeleteFile(context.Background(), "u"); !errors.Is(err, boom) {
		t.Fatalf("DeleteFile error = %v, want %v", err, boom)
	}
}

type failingDelete struct {
	routertest.FakeStorage
	err error
}

func (f failingDelete) DeleteFile(context.Context, string) error { return f.err }
