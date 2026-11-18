package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
)

// bodyLimit caps request bodies. A declared Content-Length over the limit is
// answered with 413 up front; a body without a declared length is wrapped in
// http.MaxBytesReader, so reading past the limit fails and the handler answers
// (most JSON handlers with 400, the media handler with 413).
func bodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			logID := gokit.GenerateLogId(c)
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
				gokit.ErrorResponse(http.StatusRequestEntityTooLarge, gokit.MsgInvalidRequest, logID, "request body too large"))
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
