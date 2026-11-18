package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
)

// bodyLimit caps request bodies: a declared Content-Length over the limit gets
// 413; otherwise the body is wrapped in http.MaxBytesReader so reads past it fail.
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
