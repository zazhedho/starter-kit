package handleruser

import (
	"fmt"
	"net/http"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *HandlerUser) respondTooManyLoginAttempts(ctx *gin.Context, logId uuid.UUID, ttl time.Duration) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	message := "Too many login attempts. Please try again later."
	if ttl > 0 {
		message = fmt.Sprintf("Too many login attempts. Try again in %d seconds.", int(ttl.Seconds()))
	}

	res := response.Response(http.StatusTooManyRequests, messages.MsgFail, logId, nil)
	res.Error = response.Errors{Code: http.StatusTooManyRequests, Message: message}
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}
