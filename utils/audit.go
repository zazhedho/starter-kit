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
		"is_impersonated":      true,
		"original_user_id":     strings.TrimSpace(InterfaceString(authData["original_user_id"])),
		"original_username":    strings.TrimSpace(InterfaceString(authData["original_username"])),
		"original_role":        strings.TrimSpace(InterfaceString(authData["original_role"])),
		"impersonated_user_id": strings.TrimSpace(InterfaceString(authData["user_id"])),
		"impersonated_user":    strings.TrimSpace(InterfaceString(authData["username"])),
		"impersonated_role":    strings.TrimSpace(InterfaceString(authData["role"])),
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

func RedactSensitivePayload(input interface{}) interface{} {
	normalized := NormalizePayload(input)
	return RedactSensitiveValue(normalized)
}

func RedactSensitiveValue(input interface{}) interface{} {
	switch v := input.(type) {
	case map[string]interface{}:
		return redactSensitiveMap(v)
	case []interface{}:
		return redactSensitiveSlice(v)
	default:
		return v
	}
}

func IsSensitiveKey(key string) bool {
	k := NormalizeKey(key)
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "otp")
}

func redactSensitiveMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, val := range in {
		if IsSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}

		out[k] = RedactSensitiveValue(val)
	}
	return out
}

func redactSensitiveSlice(values []interface{}) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, val := range values {
		out = append(out, RedactSensitiveValue(val))
	}
	return out
}
