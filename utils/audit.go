package utils

import (
	"encoding/json"
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

func GetImpersonationMetadata(ctx *gin.Context) map[string]interface{} {
	authData := GetAuthData(ctx)
	if authData == nil {
		return nil
	}

	isImpersonated, ok := authData["is_impersonated"].(bool)
	if !ok || !isImpersonated {
		return nil
	}

	return map[string]interface{}{
		"is_impersonated":   true,
		"original_user_id":  strings.TrimSpace(InterfaceString(authData["original_user_id"])),
		"original_username": strings.TrimSpace(InterfaceString(authData["original_username"])),
		"original_role":     strings.TrimSpace(InterfaceString(authData["original_role"])),
	}
}

func MergeMetadata(base map[string]interface{}, extra map[string]interface{}) map[string]interface{} {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}

	merged := make(map[string]interface{}, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}

	return merged
}

func InterfaceBool(data interface{}) bool {
	if data == nil {
		return false
	}

	switch v := data.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		bytes, _ := json.Marshal(data)
		return strings.EqualFold(strings.Trim(string(bytes), `"`), "true")
	}
}
