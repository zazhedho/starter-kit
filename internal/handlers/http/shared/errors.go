// Package shared holds what the HTTP handlers of every module have in common:
// how a failed request is answered and logged.
package shared

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
)

// Write answers a failed request. A 500 gets gokit's standard body, which carries
// the log ID; any other status gets the fixed envelope message for that status,
// and detail is the reason given to the caller, never an internal error's text.
func Write(ctx *gin.Context, status int, detail string) {
	logID := gokit.RequestID(ctx)
	if status == http.StatusInternalServerError {
		ctx.JSON(status, gokit.InternalServerError(logID))
		return
	}
	ctx.JSON(status, gokit.ErrorResponse(status, message(status), logID, detail))
}

// Log records why a request failed. A client error (4xx) is expected traffic and
// is logged at WARN; only a server error is logged at ERROR.
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
	case http.StatusBadGateway:
		return "An upstream service failed to answer"
	case http.StatusServiceUnavailable:
		return "The service is unavailable"
	default:
		return gokit.MsgInvalidRequest
	}
}
