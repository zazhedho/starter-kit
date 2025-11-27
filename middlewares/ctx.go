package middlewares

import (
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func SetContextId() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctxId, err := uuid.NewV7()
		if err != nil {
			ctxId = uuid.New()
		}

		ctx.Set(utils.CtxKeyId, ctxId)
		ctx.Next()
	}
}
