package media

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
	httpshared "starter-kit/internal/handlers/http/shared"
)

const (
	multipartOverhead = int64(1 << 20)
	defaultListLimit  = 20
)

// listFilters are the filters[...] keys read into typed fields below. Which
// columns may be filtered or sorted, and the default order, belong to the
// repository, the single authority for them.
var (
	errTooManyUploads     = errors.New("too many uploads are in progress, try again shortly")
	errTooManyUserUploads = errors.New("too many of your uploads are in progress, wait for one to finish")
)

var listFilters = []string{"owner_user_id", "content_type"}

type Handler struct {
	service       Service
	uploadTimeout time.Duration
	uploadSlots   chan struct{} // nil: no cap on concurrent uploads
	maxPerUser    int           // zero or less: no per-user cap
	mu            sync.Mutex
	userUploads   map[string]int // uploads in progress per user
	authkit.AuditWriter
}

// New builds the handler. A positive uploadTimeout replaces the server's read and
// write deadlines for an upload, a positive maxUploads caps the uploads in
// progress and a positive maxPerUser caps those of one user.
func New(service Service, auditService authkit.AuditService, uploadTimeout time.Duration, maxUploads, maxPerUser int) *Handler {
	h := &Handler{
		service:       service,
		uploadTimeout: uploadTimeout,
		maxPerUser:    maxPerUser,
		userUploads:   make(map[string]int),
		AuditWriter:   authkit.NewAuditWriter(auditService, "MediaHandler"),
	}
	if maxUploads > 0 {
		h.uploadSlots = make(chan struct{}, maxUploads)
	}
	return h
}

func (h *Handler) Upload(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[MediaHandler][Upload]"
	release, ok := h.acquireUploadSlot(ctx, logPrefix)
	if !ok {
		return
	}
	defer release()
	// The server-wide timeouts are shorter than an upload may need. The write
	// deadline moves too, or the response of a slow upload is cut off and the
	// client retries into a duplicate.
	if h.uploadTimeout > 0 {
		h.extendDeadlines(ctx, logPrefix)
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, h.service.MaxFileSize()+multipartOverhead)

	file, header, err := ctx.Request.FormFile("file")
	if err != nil {
		statusCode := http.StatusBadRequest
		message := "file is required"
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			statusCode = http.StatusRequestEntityTooLarge
			message = domainmedia.ErrFileTooLarge.Error()
		}
		httpshared.Log(ctx, statusCode, logPrefix, "FormFile", err)
		httpshared.Write(ctx, statusCode, message)
		return
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logus.LogContextf(ctx, logus.LevelWarn, "%s; CloseFile; Error: %v", logPrefix, closeErr)
		}
	}()

	scope := authkit.ScopeFrom(ctx.Request.Context())
	data, err := h.service.Upload(ctx.Request.Context(), scope.UserID, file, header)
	if err != nil {
		h.WriteAudit(ctx, authkit.AuditEvent{
			Action:       authkit.ActionCreate,
			Resource:     "media",
			Status:       authkit.StatusFailed,
			Message:      "Failed to upload media",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"original_name": domainmedia.SafeFilename(header.Filename),
				"size":          header.Size,
			},
		})
		fail(ctx, "Upload", err)
		return
	}

	h.WriteAudit(ctx, authkit.AuditEvent{
		Action:     authkit.ActionCreate,
		Resource:   "media",
		ResourceID: data.ID,
		Status:     authkit.StatusSuccess,
		Message:    "Uploaded media",
		AfterData:  data,
	})
	ctx.JSON(http.StatusCreated, gokit.Response(http.StatusCreated, "Media uploaded successfully", logID, data))
}

// acquireUploadSlot takes a per-user slot, then a global one, without waiting.
// A user over their own cap gets 429 before touching a global slot; a full
// process answers 503. Both log at WARN: refusing load is expected.
func (h *Handler) acquireUploadSlot(ctx *gin.Context, logPrefix string) (release func(), ok bool) {
	user := authkit.ScopeFrom(ctx.Request.Context()).UserID
	if !h.takeUserSlot(user) {
		logus.LogContextf(ctx, logus.LevelWarn, "%s; userUploadSlot; Error: %v", logPrefix, errTooManyUserUploads)
		httpshared.Write(ctx, http.StatusTooManyRequests, errTooManyUserUploads.Error())
		return nil, false
	}
	if h.uploadSlots == nil {
		return func() { h.freeUserSlot(user) }, true
	}
	select {
	case h.uploadSlots <- struct{}{}:
		return func() { <-h.uploadSlots; h.freeUserSlot(user) }, true
	default:
		h.freeUserSlot(user)
		logus.LogContextf(ctx, logus.LevelWarn, "%s; uploadSlot; Error: %v", logPrefix, errTooManyUploads)
		httpshared.Write(ctx, http.StatusServiceUnavailable, errTooManyUploads.Error())
		return nil, false
	}
}

func (h *Handler) takeUserSlot(user string) bool {
	if h.maxPerUser <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.userUploads[user] >= h.maxPerUser {
		return false
	}
	h.userUploads[user]++
	return true
}

func (h *Handler) freeUserSlot(user string) {
	if h.maxPerUser <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.userUploads[user]--; h.userUploads[user] <= 0 {
		delete(h.userUploads, user)
	}
}

// extendDeadlines moves the read and write deadlines of this connection to now
// plus the upload timeout. A writer without deadline support keeps the server's.
func (h *Handler) extendDeadlines(ctx *gin.Context, logPrefix string) {
	rc := http.NewResponseController(ctx.Writer)
	deadline := time.Now().Add(h.uploadTimeout)
	for name, set := range map[string]func(time.Time) error{"SetReadDeadline": rc.SetReadDeadline, "SetWriteDeadline": rc.SetWriteDeadline} {
		if err := set(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			logus.LogContextf(ctx, logus.LevelWarn, "%s; %s; Error: %v", logPrefix, name, err)
		}
	}
}

func (h *Handler) List(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[MediaHandler][List]"

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "", "", defaultListLimit)
	if err != nil {
		httpshared.Log(ctx, http.StatusBadRequest, logPrefix, "GetBaseParams", err)
		httpshared.Write(ctx, http.StatusBadRequest, "invalid query parameters")
		return
	}

	filters := gokit.WhitelistStringFilter(params.Filters, listFilters)
	ownerID, _ := filters["owner_user_id"].(string)
	contentType, _ := filters["content_type"].(string)
	actor := actorFrom(ctx.Request.Context())
	// Only list_any callers may filter by owner; for everyone else the value
	// is ignored, so it is not validated.
	if actor.CanListAny && ownerID != "" {
		if _, err := uuid.Parse(ownerID); err != nil {
			httpshared.Log(ctx, http.StatusBadRequest, logPrefix, "owner_user_id", err)
			httpshared.Write(ctx, http.StatusBadRequest, "owner_user_id must be a UUID")
			return
		}
	}

	result, err := h.service.List(ctx.Request.Context(), actor, dtomedia.ListRequest{
		Search:         params.Search,
		OwnerUserID:    ownerID,
		ContentType:    contentType,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
	})
	if err != nil {
		fail(ctx, "List", err)
		return
	}

	// The repository clamps the limit (gokit QueryOptions.MaxLimit) and reports
	// the one it applied; nil items serialize as [].
	ctx.JSON(http.StatusOK, gokit.PaginationResponse(http.StatusOK, result.Total, params.Page, result.Limit, logID, result.Items))
}

func (h *Handler) Delete(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return // ValidateUUIDParam has answered 400
	}

	data, err := h.service.Delete(ctx.Request.Context(), actorFrom(ctx.Request.Context()), id)
	if err != nil {
		h.WriteAudit(ctx, authkit.AuditEvent{
			Action:       authkit.ActionDelete,
			Resource:     "media",
			ResourceID:   id,
			Status:       authkit.StatusFailed,
			Message:      "Failed to delete media",
			ErrorMessage: err.Error(),
		})
		fail(ctx, "Delete", err)
		return
	}

	h.WriteAudit(ctx, authkit.AuditEvent{
		Action:     authkit.ActionDelete,
		Resource:   "media",
		ResourceID: data.ID,
		Status:     authkit.StatusSuccess,
		Message:    "Deleted media",
		BeforeData: data,
	})
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, "Media deleted successfully", logID, nil))
}

// actorFrom reduces the scope to what the media rules need. It is only right
// after Auth and LoadPermissions: Has is false without the loaded permissions.
func actorFrom(ctx context.Context) domainmedia.Actor {
	scope := authkit.ScopeFrom(ctx)
	return domainmedia.Actor{
		UserID:       scope.UserID,
		CanListAny:   scope.Has("media", "list_any"),
		CanDeleteAny: scope.Has("media", "delete_any"),
	}
}

// fail logs and answers a service error with the status mediaErrorResponse maps it to.
func fail(ctx *gin.Context, method string, err error) {
	status, detail := mediaErrorResponse(err)
	httpshared.Log(ctx, status, "[MediaHandler]["+method+"]", "Service."+method, err)
	httpshared.Write(ctx, status, detail)
}

// mediaErrorResponse is the one place service errors become HTTP statuses.
func mediaErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, domainmedia.ErrEmptyFile), errors.Is(err, domainmedia.ErrUnsupportedContentType):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, domainmedia.ErrFileTooLarge):
		return http.StatusRequestEntityTooLarge, err.Error()
	case errors.Is(err, domainmedia.ErrMediaForbidden), errors.Is(err, domainmedia.ErrNotFound):
		// A forbidden row answers like a missing one, so ids cannot be probed.
		return http.StatusNotFound, "media not found"
	default:
		return http.StatusInternalServerError, gokit.MsgSomethingWrong
	}
}
