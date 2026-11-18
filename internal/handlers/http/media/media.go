package handlermedia

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	domainmedia "starter-kit/internal/domain/media"
)

const multipartOverhead = int64(1 << 20)

type MediaHandler struct {
	service       Service
	uploadTimeout time.Duration
	authkit.AuditWriter
}

func NewMediaHandler(service Service, auditService authkit.AuditService, uploadTimeout time.Duration) *MediaHandler {
	return &MediaHandler{
		service:       service,
		uploadTimeout: uploadTimeout,
		AuditWriter:   authkit.NewAuditWriter(auditService, "MediaHandler"),
	}
}

func (h *MediaHandler) Upload(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	logPrefix := "[MediaHandler][Upload]"
	// Uploads may need longer than the server-wide read timeout.
	if h.uploadTimeout > 0 {
		rc := http.NewResponseController(ctx.Writer)
		if err := rc.SetReadDeadline(time.Now().Add(h.uploadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; SetReadDeadline; Error: %v", logPrefix, err))
		}
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
		logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; FormFile; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, gokit.ErrorResponse(statusCode, gokit.MsgInvalidRequest, logID, message))
		return
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; CloseFile; Error: %v", logPrefix, closeErr))
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
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Upload; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, gokit.ErrorResponse(statusCode, gokit.MsgInvalidRequest, logID, publicError))
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

func (h *MediaHandler) Delete(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	logPrefix := "[MediaHandler][Delete]"
	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}

	data, err := h.service.Delete(ctx.Request.Context(), authkit.ScopeFrom(ctx.Request.Context()), id)
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
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, publicError))
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
