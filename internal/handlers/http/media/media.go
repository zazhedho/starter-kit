package handlermedia

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/authscope"
	domainaudit "github.com/zazhedho/authkit/domain/audit"
	"github.com/zazhedho/authkit/handlers/auditwriter"
	interfaceaudit "github.com/zazhedho/authkit/interfaces/audit"
	"github.com/zazhedho/gokit/handlercommon"
	"github.com/zazhedho/gokit/messages"
	"github.com/zazhedho/gokit/response"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	domainmedia "starter-kit/internal/domain/media"
	interfacemedia "starter-kit/internal/interfaces/media"
)

const multipartOverhead = int64(1 << 20)

type MediaHandler struct {
	Service       interfacemedia.ServiceMediaInterface
	uploadTimeout time.Duration
	auditwriter.AuditWriter
}

func NewMediaHandler(service interfacemedia.ServiceMediaInterface, auditService interfaceaudit.ServiceAuditInterface, uploadTimeout time.Duration) *MediaHandler {
	return &MediaHandler{
		Service:       service,
		uploadTimeout: uploadTimeout,
		AuditWriter:   auditwriter.NewAuditWriter(auditService, "MediaHandler"),
	}
}

func (h *MediaHandler) Upload(ctx *gin.Context) {
	logID := utils.GenerateLogId(ctx)
	logPrefix := "[MediaHandler][Upload]"
	// Uploads may need longer than the server-wide read timeout.
	if h.uploadTimeout > 0 {
		rc := http.NewResponseController(ctx.Writer)
		if err := rc.SetReadDeadline(time.Now().Add(h.uploadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; SetReadDeadline; Error: %v", logPrefix, err))
		}
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, h.Service.MaxFileSize()+multipartOverhead)

	file, header, err := ctx.Request.FormFile("file")
	if err != nil {
		statusCode := http.StatusBadRequest
		message := "file is required"
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			statusCode = http.StatusRequestEntityTooLarge
			message = domainmedia.ErrFileTooLarge.Error()
		}
		logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; FormFile; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, response.ErrorResponse(statusCode, messages.InvalidRequest, logID, message))
		return
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; CloseFile; Error: %v", logPrefix, closeErr))
		}
	}()

	scope := authscope.FromContext(ctx.Request.Context())
	data, err := h.Service.Upload(ctx.Request.Context(), scope.UserID, file, header)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "media",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to upload media",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"original_name": header.Filename,
				"size":          header.Size,
			},
		})

		statusCode, publicError := mediaErrorResponse(err)
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Upload; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, response.ErrorResponse(statusCode, messages.InvalidRequest, logID, publicError))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "media",
		ResourceID: data.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Uploaded media",
		AfterData:  data,
	})
	ctx.JSON(http.StatusCreated, response.Response(http.StatusCreated, "Media uploaded successfully", logID, data))
}

func (h *MediaHandler) Delete(ctx *gin.Context) {
	logID := utils.GenerateLogId(ctx)
	logPrefix := "[MediaHandler][Delete]"
	id, err := handlercommon.ValidateUUID(ctx, logID)
	if err != nil {
		return
	}

	data, err := h.Service.Delete(ctx.Request.Context(), authscope.FromContext(ctx.Request.Context()), id)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "media",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete media",
			ErrorMessage: err.Error(),
		})

		statusCode, publicError := mediaErrorResponse(err)
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %v", logPrefix, err))
		ctx.JSON(statusCode, response.ErrorResponse(statusCode, messages.MsgSomethingWrong, logID, publicError))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "media",
		ResourceID: data.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted media",
		BeforeData: data,
	})
	ctx.JSON(http.StatusOK, response.Response(http.StatusOK, "Media deleted successfully", logID, nil))
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
	case errors.Is(err, gorm.ErrRecordNotFound):
		return http.StatusNotFound, "media not found"
	default:
		return http.StatusInternalServerError, messages.MsgSomethingWrong
	}
}
