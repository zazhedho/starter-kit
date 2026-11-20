package shared

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
)

// Write answers with detail as the reason shown to the caller, never an internal error's text.
func Write(ctx *gin.Context, status int, detail string) {
	logID := gokit.RequestID(ctx)
	if status == http.StatusInternalServerError {
		ctx.JSON(status, gokit.InternalServerError(logID))
		return
	}
	ctx.JSON(status, gokit.ErrorResponse(status, message(status), logID, detail))
}

func Log(ctx *gin.Context, status int, prefix, operation string, err error) {
	level := logus.LevelError
	if status < http.StatusInternalServerError {
		level = logus.LevelWarn
	}
	logus.LogContextf(ctx, level, "%s; %s; Error: %v", prefix, operation, err)
}

func message(status int) string {
	switch status {
	case http.StatusNotFound:
		return gokit.MsgResourceNotFound
	case http.StatusConflict:
		return "The request conflicts with the current state of the resource"
	case http.StatusRequestEntityTooLarge:
		return gokit.MsgRequestTooLarge
	case http.StatusTooManyRequests:
		return "Too many requests"
	case http.StatusBadGateway:
		return "An upstream service failed to answer"
	case http.StatusServiceUnavailable:
		return "The service is unavailable"
	default:
		return gokit.MsgInvalidRequest
	}
}
