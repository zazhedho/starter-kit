package utils

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func GetRequestID(ctx *gin.Context) string {
	if raw, ok := ctx.Get(CtxKeyId); ok && raw != nil {
		switch v := raw.(type) {
		case uuid.UUID:
			return v.String()
		case string:
			return strings.TrimSpace(v)
		}
	}

	return GenerateLogId(ctx).String()
}

func GetActorContext(ctx *gin.Context) (string, string) {
	authData := GetAuthData(ctx)
	if authData == nil {
		return "", ""
	}

	userID := strings.TrimSpace(InterfaceString(authData["user_id"]))
	role := strings.TrimSpace(InterfaceString(authData["role"]))
	return userID, role
}
