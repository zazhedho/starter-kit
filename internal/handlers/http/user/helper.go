package handleruser

import (
	"fmt"
	"net/http"
	domainaudit "starter-kit/internal/domain/audit"
	handlercommon "starter-kit/internal/handlers/http/common"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	defaultConfigRegisterOTPEnabled        = "auth.register_otp_enabled"
	defaultConfigPasswordResetEmailEnabled = "auth.password_reset_email_enabled"
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

func (h *HandlerUser) respondThrottle(ctx *gin.Context, logId uuid.UUID, ttl time.Duration, message string) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	if message == "" {
		message = "Too many requests. Please try again later."
	}

	res := response.Response(http.StatusTooManyRequests, messages.MsgFail, logId, nil)
	res.Error = response.Errors{Code: http.StatusTooManyRequests, Message: message}
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *HandlerUser) writeAudit(ctx *gin.Context, event domainaudit.AuditEvent) {
	handlercommon.WriteAudit(ctx, h.AuditService, event, "UserHandler")
}

func (h *HandlerUser) isRuntimeConfigEnabled(configKey string, fallback bool) (bool, error) {
	if h.AppConfigService == nil {
		return fallback, nil
	}
	return h.AppConfigService.IsEnabled(configKey, fallback)
}

func registerOTPConfigKey() string {
	return utils.GetEnv("CONFIG_REGISTER_OTP", defaultConfigRegisterOTPEnabled)
}

func passwordResetEmailConfigKey() string {
	return utils.GetEnv("CONFIG_PASSWORD_RESET_EMAIL", defaultConfigPasswordResetEmailEnabled)
}

func authEmailAppName() string {
	appName := utils.GetEnv("AUTH_EMAIL_APP_NAME", "")
	if appName != "" {
		return appName
	}
	return utils.GetEnv("APP_NAME", "STARTER-KIT")
}

func buildAuthTokenResponse(accessToken string, refreshToken string) map[string]interface{} {
	data := map[string]interface{}{
		"access_token":     accessToken,
		"token_type":       "Bearer",
		"expires_in_hours": utils.GetEnv("JWT_EXP", 24),
	}

	if refreshToken != "" {
		data["refresh_token"] = refreshToken
		data["refresh_expires_in_hours"] = utils.GetEnv("REFRESH_TOKEN_EXP_HOURS", 168)
	}

	return data
}

func buildImpersonationClaimsOverrideFromClaims(claims map[string]interface{}) *utils.AppClaims {
	if claims == nil || !utils.InterfaceBool(claims["is_impersonated"]) {
		return nil
	}

	return &utils.AppClaims{
		IsImpersonated:   true,
		OriginalUserId:   utils.InterfaceString(claims["original_user_id"]),
		OriginalUsername: utils.InterfaceString(claims["original_username"]),
		OriginalRole:     utils.InterfaceString(claims["original_role"]),
	}
}
