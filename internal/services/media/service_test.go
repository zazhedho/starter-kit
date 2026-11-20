package media

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/textproto"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
	"starter-kit/internal/testutil/logcapture"
)

// logs captures what the service logs during the tests (see logcapture).
var logs *logcapture.Capture

func TestMain(m *testing.M) {
	logs = logcapture.Start()
	code := m.Run()
	if code != 0 {
		_, _ = os.Stderr.WriteString(logs.All())
	}
	logs.Stop()
	os.Exit(code)
}

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

func (m *mediaRepoMock) List(_ context.Context, req dtomedia.ListRequest) (dtomedia.ListResult, error) {
	m.listed = req
	return dtomedia.ListResult{Items: m.listItems, Total: m.listTotal, Limit: 20}, m.listErr
}

func (m *mediaRepoMock) Store(_ context.Context, media *domainmedia.Media) error {
	m.stored = *media
	return m.storeErr
}

func (m *mediaRepoMock) GetByID(_ context.Context, _ string) (domainmedia.Media, error) {
	return m.media, m.getErr
}

func (m *mediaRepoMock) Delete(_ context.Context, id string) error {
	m.deletedID = id
	return m.deleteErr
}

// storedFile is what the storage mock reports for an upload.
type storedFile struct{ objectName, url string }

type mediaStorageMock struct {
	uploadedHeader *multipart.FileHeader
	uploadResult   storedFile
	uploadErr      error
	deletedObject  string
	deleteCtxErr   error // the context's error when DeleteObject was called
	deleteHasLimit bool  // the context carried a deadline then
	deleteErr      error
}

func (m *mediaStorageMock) UploadFile(_ context.Context, _ multipart.File, header *multipart.FileHeader, _ string) (string, string, error) {
	m.uploadedHeader = header
	return m.uploadResult.objectName, m.uploadResult.url, m.uploadErr
}

func (m *mediaStorageMock) DeleteObject(ctx context.Context, objectName string) error {
	m.deletedObject, m.deleteCtxErr = objectName, ctx.Err()
	_, m.deleteHasLimit = ctx.Deadline()
	return m.deleteErr
}

func newMediaHeader(filename string, size int64) *multipart.FileHeader {
	return &multipart.FileHeader{Filename: filename, Size: size, Header: textproto.MIMEHeader{}}
}

func TestUploadDetectsContentAndStoresMetadata(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	repo := &mediaRepoMock{}
	storageMock := &mediaStorageMock{uploadResult: storedFile{"media/generated.png", "https://cdn/media/generated.png"}}
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
	storageMock := &mediaStorageMock{uploadResult: storedFile{"media/generated.png", "https://cdn/media/generated.png"}}
	service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

	_, err := service.Upload(context.Background(), uuid.NewString(), mediaTestFile{bytes.NewReader(png)}, newMediaHeader("avatar.png", int64(len(png))))
	if !errors.Is(err, repoErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
	if storageMock.deletedObject != storageMock.uploadResult.objectName {
		t.Fatalf("expected uploaded object cleanup by its name, got %q", storageMock.deletedObject)
	}
}

func TestDeleteEnforcesOwnership(t *testing.T) {
	ownerID := uuid.NewString()
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: ownerID, ObjectKey: "media/file.png", URL: "https://cdn/media/file.png"}

	t.Run("owner", func(t *testing.T) {
		repo := &mediaRepoMock{media: media}
		storageMock := &mediaStorageMock{}
		service := NewService(repo, storageMock, Options{MaxFileSize: 1024})

		if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: ownerID}, media.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if storageMock.deletedObject != media.ObjectKey || repo.deletedID != media.ID {
			t.Fatalf("expected storage and metadata deletion, got object=%q id=%q", storageMock.deletedObject, repo.deletedID)
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
		if storageMock.deletedObject != "" || repo.deletedID != "" {
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
	storageMock := &mediaStorageMock{uploadResult: storedFile{"media/x.png", "https://cdn/media/x.png"}}
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
	storageMock := &mediaStorageMock{uploadResult: storedFile{"media/x.png", "https://cdn/media/x.png"}}
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
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: ownerID, ObjectKey: "media/file.png", URL: "https://cdn/media/file.png"}
	service := NewService(&mediaRepoMock{media: media}, &mediaStorageMock{}, Options{})
	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: "  " + ownerID + " "}, media.ID); err != nil {
		t.Fatalf("delete with padded actor id: %v", err)
	}
}

func TestDeleteOtherWithoutDeleteAnyIsForbidden(t *testing.T) {
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: uuid.NewString(), ObjectKey: "media/file.png", URL: "https://cdn/media/file.png"}
	repo := &mediaRepoMock{media: media}
	storageMock := &mediaStorageMock{}
	service := NewService(repo, storageMock, Options{})

	// CanListAny must not leak into delete rights.
	_, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString(), CanListAny: true}, media.ID)
	if !errors.Is(err, domainmedia.ErrMediaForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	if storageMock.deletedObject != "" || repo.deletedID != "" {
		t.Fatal("forbidden delete must leave storage and metadata untouched")
	}
}

func TestDeleteOtherWithDeleteAny(t *testing.T) {
	media := domainmedia.Media{ID: uuid.NewString(), OwnerUserID: uuid.NewString(), ObjectKey: "media/file.png", URL: "https://cdn/media/file.png"}
	repo := &mediaRepoMock{media: media}
	storageMock := &mediaStorageMock{}
	service := NewService(repo, storageMock, Options{})

	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: uuid.NewString(), CanDeleteAny: true}, media.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if storageMock.deletedObject != media.ObjectKey || repo.deletedID != media.ID {
		t.Fatalf("expected storage and metadata deletion, got object=%q id=%q", storageMock.deletedObject, repo.deletedID)
	}
}

func TestListOwnOnlyWithoutListAny(t *testing.T) {
	me, other := uuid.NewString(), uuid.NewString()
	repo := &mediaRepoMock{listItems: []domainmedia.Media{{ID: "m-1"}}, listTotal: 1}
	service := NewService(repo, &mediaStorageMock{}, Options{})

	result, err := service.List(context.Background(), domainmedia.Actor{UserID: " " + me + " ", CanDeleteAny: true}, dtomedia.ListRequest{OwnerUserID: other, Search: "cat"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if repo.listed.OwnerUserID != me {
		t.Fatalf("owner filter is %q, want the caller %q", repo.listed.OwnerUserID, me)
	}
	if repo.listed.Search != "cat" || len(result.Items) != 1 || result.Total != 1 || result.Limit != 20 {
		t.Fatalf("other fields must pass through: %+v result=%+v", repo.listed, result)
	}

	if _, err := service.List(context.Background(), domainmedia.Actor{UserID: me}, dtomedia.ListRequest{}); err != nil || repo.listed.OwnerUserID != me {
		t.Fatalf("an empty filter must also be forced to the caller, got %q err %v", repo.listed.OwnerUserID, err)
	}
}

func TestListAnyHonorsOwnerFilter(t *testing.T) {
	other := uuid.NewString()
	repo := &mediaRepoMock{}
	service := NewService(repo, &mediaStorageMock{}, Options{})
	actor := domainmedia.Actor{UserID: uuid.NewString(), CanListAny: true}

	if _, err := service.List(context.Background(), actor, dtomedia.ListRequest{OwnerUserID: other}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if repo.listed.OwnerUserID != other {
		t.Fatalf("owner filter is %q, want %q", repo.listed.OwnerUserID, other)
	}

	if _, err := service.List(context.Background(), actor, dtomedia.ListRequest{}); err != nil || repo.listed.OwnerUserID != "" {
		t.Fatalf("list_any without a filter must stay unfiltered, got %q err %v", repo.listed.OwnerUserID, err)
	}
}

func TestListReturnsRepositoryErrors(t *testing.T) {
	boom := errors.New("db down")
	service := NewService(&mediaRepoMock{listErr: boom}, &mediaStorageMock{}, Options{})
	if _, err := service.List(context.Background(), domainmedia.Actor{UserID: uuid.NewString()}, dtomedia.ListRequest{}); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the repository error", err)
	}
}

// A media row keeps the object key the storage returned; the URL is built from
// the base URL at upload time and goes stale when that changes.
func TestDeleteUsesTheStoredObjectKeyNotTheURL(t *testing.T) {
	ownerID := uuid.NewString()
	media := domainmedia.Media{
		ID: uuid.NewString(), OwnerUserID: ownerID,
		ObjectKey: "media/20260101_000000_abc.png",
		URL:       "https://old-cdn.example.test/old-bucket/media/other-name.png",
	}
	storageMock := &mediaStorageMock{}
	service := NewService(&mediaRepoMock{media: media}, storageMock, Options{})

	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: ownerID}, media.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if storageMock.deletedObject != media.ObjectKey {
		t.Fatalf("deleted %q, want the stored object key %q", storageMock.deletedObject, media.ObjectKey)
	}
}

func TestDeleteKeepsTheRowWhenTheObjectCannotBeDeleted(t *testing.T) {
	ownerID := uuid.NewString()
	repo := &mediaRepoMock{media: domainmedia.Media{ID: uuid.NewString(), OwnerUserID: ownerID, ObjectKey: "media/x.png"}}
	boom := errors.New("storage down")
	service := NewService(repo, &mediaStorageMock{deleteErr: boom}, Options{})

	if _, err := service.Delete(context.Background(), domainmedia.Actor{UserID: ownerID}, repo.media.ID); !errors.Is(err, boom) {
		t.Fatalf("Delete = %v, want the storage error", err)
	}
	if repo.deletedID != "" {
		t.Fatal("the row must stay when its object could not be deleted")
	}
}

// The request may already be canceled (a client that gave up); the orphan must
// still be removed, with its own short deadline, and a failure must be logged.
func TestOrphanCleanupSurvivesACanceledRequestAndLogsFailures(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	storageMock := &mediaStorageMock{
		uploadResult: storedFile{"media/orphan.png", "https://cdn/media/orphan.png"},
		deleteErr:    errors.New("storage unreachable"),
	}
	service := NewService(&mediaRepoMock{storeErr: errors.New("database unavailable")}, storageMock, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mark := logs.Mark()
	_, err := service.Upload(ctx, uuid.NewString(), mediaTestFile{bytes.NewReader(png)}, newMediaHeader("a.png", int64(len(png))))
	if err == nil {
		t.Fatal("Upload must fail when the metadata cannot be stored")
	}
	if storageMock.deletedObject != "media/orphan.png" {
		t.Fatalf("the orphan %q was not removed", storageMock.deletedObject)
	}
	if storageMock.deleteCtxErr != nil {
		t.Fatalf("cleanup used a canceled context: %v", storageMock.deleteCtxErr)
	}
	if !storageMock.deleteHasLimit {
		t.Fatal("cleanup must run under its own deadline")
	}
	if out := logs.Since(mark); !strings.Contains(out, "media/orphan.png") || !strings.Contains(out, "storage unreachable") {
		t.Fatalf("a failed cleanup must be logged with the object and the cause, got: %s", out)
	}
}
