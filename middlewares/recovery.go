package middlewares

import (
	"fmt"
	"net/http"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ErrorHandler(c *gin.Context, err any) {
	logId, _ := c.Value(utils.CtxKeyId).(uuid.UUID)
	logger.WriteLog(logger.LogLevelPanic, fmt.Sprintf("RECOVERY: %s; Error: %+v;", logId.String(), err))

	res := response.Response(http.StatusInternalServerError, fmt.Sprintf("%s (%s)", messages.MsgFail, logId.String()), logId, nil)
	c.AbortWithStatusJSON(http.StatusInternalServerError, res)
	return
}
