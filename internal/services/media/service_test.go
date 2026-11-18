package media

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/textproto"
	"testing"

	"github.com/google/uuid"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

type mediaTestFile struct {
	*bytes.Reader
}

func (mediaTestFile) Close() error { return nil }

type mediaRepoMock struct {
	stored    domainmedia.Media
	storeErr  error
	media     domainmedia.Media
	getErr    error
	deletedID string
	deleteErr error

	listed    dtomedia.ListRequest
	listItems []domainmedia.Media
	listTotal int64
	listErr   error
}

func (m *mediaRepoMock) List(_ context.Context, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error) {
	m.listed = req
	return m.listItems, m.listTotal, m.listErr
}

func (m *mediaRepoMock) Store(_ context.Context, media domainmedia.Media) error {
	m.stored = media
	return m.storeErr
}

func (m *mediaRepoMock) GetByID(_ context.Context, _ string) (domainmedia.Media, error) {
	return m.media, m.getErr
}

func (m *mediaRepoMock) Delete(_ context.Context, id string) error {
	m.deletedID = id
	return m.deleteErr
}

type mediaStorageMock struct {
	uploadedHeader *multipart.FileHeader
	uploadResult   domainmedia.StoredFile
	uploadErr      error
	deletedURL     string
	deleteErr      error
}

func (m *mediaStorageMock) UploadFile(_ context.Context, _ multipart.File, header *multipart.FileHeader, _ string) (domainmedia.StoredFile, error) {
	m.uploadedHeader = header
	return m.uploadResult, m.uploadErr
}

func (m *mediaStorageMock) DeleteFile(_ context.Context, fileURL string) error {
	m.deletedURL = fileURL
	return m.deleteErr
}

func newMediaHeader(filename string, size int64) *multipart.FileHeader {
	return &multipart.FileHeader{Filename: filename, Size: size, Header: textproto.MIMEHeader{}}
}

func TestUploadDetectsContentAndStoresMetadata(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	repo := &mediaRepoMock{}
	storageMock := &mediaStorageMock{uploadResult: domainmedia.StoredFile{ObjectName: "media/generated.png", URL: "https://cdn/media/generated.png"}}
	service := NewService(repo, storageMock, Options{MaxFileSize: 1024})
	ownerID := uuid.NewString()

	media, err := service.Upload(context.Background(), ownerID, mediaTestFile{bytes.NewReader(png)}, newMediaHeader("../avatar.exe", int64(len(png))))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if media.OwnerUserID != ownerID || media.ObjectKey != "media/generated.png" || media.OriginalName != "avatar.exe" {
		t.Fatalf("unexpected media metadata: %+v", media)
	}
	if media.ContentType != "image/png" || storageMock.uploadedHeader.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("expected detected image/png, got media=%q header=%q", media.ContentType, storageMock.uploadedHeader.Header.Get("Content-Type"))
	}
	if storageMock.uploadedHeader.Filename != "upload.png" {
		t.Fatalf("expected server-controlled filename, got %q", storageMock.uploadedHeader.Filename)
	}
}

func TestUploadRejectsInvalidFilesBeforeStorage(t *testing.T) {
	ownerID := uuid.NewString()
	tests := []struct {
		name    string
		data    []byte
		header  *multipart.FileHeader
		maxSize int64
		wantErr error
	}{
		{name: "empty", header: newMediaHeader("empty.png", 0), maxSize: 10, wantErr: domainmedia.ErrEmptyFile},
		{name: "too large", data: []byte("large"), header: newMediaHeader("large.png", 6), maxSize: 5, wantErr: domainmedia.ErrFileTooLarge},
		{name: "unsupported content", data: []byte("plain text"), header: newMediaHeader("fake.png", 10), maxSize: 20, wantErr: domainmedia.ErrUnsupportedContentType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageMock := &mediaStorageMock{}
			service := NewService(&mediaRepoMock{}, storageMock, Options{MaxFileSize: tt.maxSize})
			_, err := service.Upload(context.Background(), ownerID, mediaTestFile{bytes.NewReader(tt.data)}, tt.header)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
			if storageMock.uploadedHeader != nil {
				t.Fatal("storage must not be called for rejected file")
			}
		})
	}
}

func TestUploadDeletesObjectWhenMetadataStoreFails(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	repoErr := errors.New("database unavailable")
	repo := &mediaRepoMock{storeErr: repoErr}
	storageMock := &mediaStorageMock{uploadResult: domainmedia.StoredFile{ObjectName: "media/generated.png", URL: "https://cdn/media/generated.png"}}
	service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

	_, err := service.Upload(context.Background(), uuid.NewString(), mediaTestFile{bytes.NewReader(png)}, newMediaHeader("avatar.png", int64(len(png))))
	if !errors.Is(err, repoErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
	if storageMock.deletedURL != storageMock.uploadResult.URL {
		t.Fatalf("expected uploaded object cleanup, got %q", storageMock.deletedURL)
	}
}

func TestDeleteEnforcesOwnership(t *testing.T) {
	ownerID := uuid.NewString()
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: ownerID, URL: "https://cdn/media/file.png"}

	t.Run("owner", func(t *testing.T) {
		repo := &mediaRepoMock{media: media}
		storageMock := &mediaStorageMock{}
		service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

		if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: ownerID}, media.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if storageMock.deletedURL != media.URL || repo.deletedID != media.ID {
			t.Fatalf("expected storage and metadata deletion, got url=%q id=%q", storageMock.deletedURL, repo.deletedID)
		}
	})

	t.Run("other user", func(t *testing.T) {
		repo := &mediaRepoMock{media: media}
		storageMock := &mediaStorageMock{}
		service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

		_, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString()}, media.ID)
		if !errors.Is(err, domainmedia.ErrMediaForbidden) {
			t.Fatalf("expected forbidden, got %v", err)
		}
		if storageMock.deletedURL != "" || repo.deletedID != "" {
			t.Fatal("forbidden delete must not mutate storage or metadata")
		}
	})

	t.Run("delete any", func(t *testing.T) {
		repo := &mediaRepoMock{media: media}
		storageMock := &mediaStorageMock{}
		service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

		if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString(), CanDeleteAny: true}, media.ID); err != nil {
			t.Fatalf("delete with delete_any: %v", err)
		}
	})
}

func TestUploadUsesTheInjectedIDGenerator(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	repo := &mediaRepoMock{}
	storageMock := &mediaStorageMock{uploadResult: domainmedia.StoredFile{ObjectName: "media/x.png", URL: "https://cdn/media/x.png"}}
	service := NewService(repo, storageMock, Options{NewID: func() string { return "fixed-id" }})

	media, err := service.Upload(context.Background(), uuid.NewString(), mediaTestFile{bytes.NewReader(png)}, newMediaHeader("a.png", int64(len(png))))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if media.ID != "fixed-id" || repo.stored.ID != "fixed-id" {
		t.Fatalf("injected id not used: returned %q, stored %q", media.ID, repo.stored.ID)
	}
}

// Without an injected generator the service issues UUIDv7 ids, the same
// version gokit.CreateUUID produces, so ids stay time-ordered.
func TestUploadDefaultIDIsUUIDv7(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	storageMock := &mediaStorageMock{uploadResult: domainmedia.StoredFile{ObjectName: "media/x.png", URL: "https://cdn/media/x.png"}}
	service := NewService(&mediaRepoMock{}, storageMock, Options{})

	media, err := service.Upload(context.Background(), uuid.NewString(), mediaTestFile{bytes.NewReader(png)}, newMediaHeader("a.png", int64(len(png))))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	id, err := uuid.Parse(media.ID)
	if err != nil || id.Version() != 7 {
		t.Fatalf("id %q is not a UUIDv7 (err=%v)", media.ID, err)
	}
}

func TestDeleteTrimsTheActorUserID(t *testing.T) {
	ownerID := uuid.NewString()
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: ownerID, URL: "https://cdn/media/file.png"}
	service := NewService(&mediaRepoMock{media: media}, &mediaStorageMock{}, Options{})
	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: "  " + ownerID + " "}, media.ID); err != nil {
		t.Fatalf("delete with padded actor id: %v", err)
	}
}

func TestDeleteOtherWithoutDeleteAnyIsForbidden(t *testing.T) {
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: uuid.NewString(), URL: "https://cdn/media/file.png"}
	repo := &mediaRepoMock{media: media}
	storageMock := &mediaStorageMock{}
	service := NewService(repo, storageMock, Options{})

	// CanListAny must not leak into delete rights.
	_, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString(), CanListAny: true}, media.ID)
	if !errors.Is(err, domainmedia.ErrMediaForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	if storageMock.deletedURL != "" || repo.deletedID != "" {
		t.Fatal("forbidden delete must leave storage and metadata untouched")
	}
}

func TestDeleteOtherWithDeleteAny(t *testing.T) {
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: uuid.NewString(), URL: "https://cdn/media/file.png"}
	repo := &mediaRepoMock{media: media}
	storageMock := &mediaStorageMock{}
	service := NewService(repo, storageMock, Options{})

	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString(), CanDeleteAny: true}, media.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if storageMock.deletedURL != media.URL || repo.deletedID != media.ID {
		t.Fatalf("expected storage and metadata deletion, got url=%q id=%q", storageMock.deletedURL, repo.deletedID)
	}
}

func TestListOwnOnlyWithoutListAny(t *testing.T) {
	me, other := uuid.NewString(), uuid.NewString()
	repo := &mediaRepoMock{listItems: []domainmedia.Media{{ID: "m-1"}}, listTotal: 1}
	service := NewService(repo, &mediaStorageMock{}, Options{})

	items, total, err := service.List(context.Background(), domainmedia.Actor{UserID: " " + me + " ", CanDeleteAny: true}, dtomedia.ListRequest{OwnerUserID: other, Search: "cat"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if repo.listed.OwnerUserID != me {
		t.Fatalf("owner filter is %q, want the caller %q", repo.listed.OwnerUserID, me)
	}
	if repo.listed.Search != "cat" || len(items) != 1 || total != 1 {
		t.Fatalf("other fields must pass through: %+v items=%d total=%d", repo.listed, len(items), total)
	}

	if _, _, err := service.List(context.Background(), domainmedia.Actor{UserID: me}, dtomedia.ListRequest{}); err != nil || repo.listed.OwnerUserID != me {
		t.Fatalf("an empty filter must also be forced to the caller, got %q err %v", repo.listed.OwnerUserID, err)
	}
}

func TestListAnyHonorsOwnerFilter(t *testing.T) {
	other := uuid.NewString()
	repo := &mediaRepoMock{}
	service := NewService(repo, &mediaStorageMock{}, Options{})
	actor := domainmedia.Actor{UserID: uuid.NewString(), CanListAny: true}

	if _, _, err := service.List(context.Background(), actor, dtomedia.ListRequest{OwnerUserID: other}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if repo.listed.OwnerUserID != other {
		t.Fatalf("owner filter is %q, want %q", repo.listed.OwnerUserID, other)
	}

	if _, _, err := service.List(context.Background(), actor, dtomedia.ListRequest{}); err != nil || repo.listed.OwnerUserID != "" {
		t.Fatalf("list_any without a filter must stay unfiltered, got %q err %v", repo.listed.OwnerUserID, err)
	}
}

func TestListReturnsRepositoryErrors(t *testing.T) {
	boom := errors.New("db down")
	service := NewService(&mediaRepoMock{listErr: boom}, &mediaStorageMock{}, Options{})
	if _, _, err := service.List(context.Background(), domainmedia.Actor{UserID: uuid.NewString()}, dtomedia.ListRequest{}); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the repository error", err)
	}
}
