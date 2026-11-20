package media

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
)

const (
	multipartOverhead = int64(1 << 20)
	defaultListLimit  = 20
)

// listFilters are the filters[...] keys read into typed fields below. Which
// columns may be filtered or sorted, and the default order, belong to the
// repository, the single authority for them.
var listFilters = []string{"owner_user_id", "content_type"}

type Handler struct {
	service       Service
	uploadTimeout time.Duration
	authkit.AuditWriter
}

func New(service Service, auditService authkit.AuditService, uploadTimeout time.Duration) *Handler {
	return &Handler{
		service:       service,
		uploadTimeout: uploadTimeout,
		AuditWriter:   authkit.NewAuditWriter(auditService, "MediaHandler"),
	}
}

func (h *Handler) Upload(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[MediaHandler][Upload]"
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
		logus.LogContextf(ctx, logus.LevelWarn, "%s; FormFile; Error: %v", logPrefix, err)
		ctx.JSON(statusCode, gokit.ErrorResponse(statusCode, mediaMessage(statusCode), logID, message))
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
				"original_name": header.Filename,
				"size":          header.Size,
			},
		})

		statusCode, publicError := mediaErrorResponse(err)
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.Upload; Error: %v", logPrefix, err)
		writeMediaError(ctx, logID, statusCode, publicError)
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
		logus.LogContextf(ctx, logus.LevelWarn, "%s; GetBaseParams; Error: %v", logPrefix, err)
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "invalid query parameters"))
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
			ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "owner_user_id must be a UUID"))
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.List; Error: %v", logPrefix, err)
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	// The repository clamps the limit (gokit QueryOptions.MaxLimit) and reports
	// the one it applied; nil items serialize as [].
	ctx.JSON(http.StatusOK, gokit.PaginationResponse(http.StatusOK, result.Total, params.Page, result.Limit, logID, result.Items))
}

func (h *Handler) Delete(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[MediaHandler][Delete]"
	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
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

		statusCode, publicError := mediaErrorResponse(err)
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.Delete; Error: %v", logPrefix, err)
		writeMediaError(ctx, logID, statusCode, publicError)
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

// writeMediaError answers with the standard 500 body for a plain server error
// and with the mapped status otherwise. The envelope message is a fixed text
// for the status; publicError is the caller-safe detail.
func writeMediaError(ctx *gin.Context, logID uuid.UUID, statusCode int, publicError string) {
	if statusCode == http.StatusInternalServerError {
		ctx.JSON(statusCode, gokit.InternalServerError(logID))
		return
	}
	ctx.JSON(statusCode, gokit.ErrorResponse(statusCode, mediaMessage(statusCode), logID, publicError))
}

func mediaMessage(statusCode int) string {
	switch statusCode {
	case http.StatusNotFound:
		return gokit.MsgResourceNotFound
	case http.StatusRequestEntityTooLarge:
		return gokit.MsgRequestTooLarge
	default:
		return gokit.MsgInvalidRequest
	}
}

func mediaErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, domainmedia.ErrEmptyFile), errors.Is(err, domainmedia.ErrUnsupportedContentType):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, domainmedia.ErrFileTooLarge):
		return http.StatusRequestEntityTooLarge, err.Error()
	case errors.Is(err, domainmedia.ErrMediaForbidden):
		// Avoid disclosing whether another user's media ID exists.
		return http.StatusNotFound, "media not found"
	case errors.Is(err, domainmedia.ErrNotFound):
		return http.StatusNotFound, "media not found"
	default:
		return http.StatusInternalServerError, gokit.MsgSomethingWrong
	}
}
