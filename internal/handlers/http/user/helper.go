package handleruser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	domainaudit "starter-kit/internal/domain/audit"
	domainsession "starter-kit/internal/domain/session"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	servicereset "starter-kit/internal/services/reset"
	"starter-kit/pkg/config"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultConfigPublicRegistrationEnabled = "auth.public_registration_enabled"
	defaultConfigRegisterOTPEnabled        = "auth.register_otp_enabled"
	defaultConfigPasswordResetEmailEnabled = "auth.password_reset_email_enabled"
	publicRegistrationDisabledMessage      = "Public registration is currently disabled."
	registrationOTPNotConfiguredMessage    = "registration OTP service is not configured"
	passwordResetEmailNotConfiguredMessage = "password reset email service is not configured"
	failedRenewLoginSessionMessage         = "Failed to renew login session"
	userNotFoundMessage                    = "user not found"
)

func (h *HandlerUser) respondTooManyLoginAttempts(ctx *gin.Context, logId uuid.UUID, ttl time.Duration) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	message := "Too many login attempts. Please try again later."
	if ttl > 0 {
		message = fmt.Sprintf("Too many login attempts. Try again in %d seconds.", int(ttl.Seconds()))
	}

	res := response.Response(http.StatusTooManyRequests, messages.MsgSomethingWrong, logId, nil)
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

	res := response.Response(http.StatusTooManyRequests, messages.MsgSomethingWrong, logId, nil)
	res.Error = response.Errors{Code: http.StatusTooManyRequests, Message: message}
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *HandlerUser) registrationConflict(ctx context.Context, email, phone string) (string, string, error) {
	user, err := h.Service.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "Service.GetUserByEmail", err
	}
	if user.Id != "" {
		return "email already exists", "", nil
	}
	if phone == "" {
		return "", "", nil
	}

	user, err = h.Service.GetUserByPhone(ctx, utils.NormalizePhoneTo62(phone))
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "Service.GetUserByPhone", err
	}
	if user.Id != "" {
		return "phone number already exists", "", nil
	}
	return "", "", nil
}

func (h *HandlerUser) rejectBlockedLogin(ctx *gin.Context, logId uuid.UUID, logPrefix, loginIdentifier, normalizedIdentifier string) bool {
	if h.LoginLimiter == nil {
		return false
	}
	blocked, ttl, err := h.LoginLimiter.IsBlocked(ctx.Request.Context(), loginIdentifier)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.IsBlocked error: %v", logPrefix, err))
		return false
	}
	if !blocked {
		return false
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogin,
		Resource: "auth",
		Status:   domainaudit.StatusFailed,
		Message:  "Login blocked due to too many attempts",
		AfterData: map[string]any{
			"identifier": normalizedIdentifier,
		},
	})
	logger.WriteLogWithContext(ctx, logger.LogLevelWarn, fmt.Sprintf("%s; Too many attempts", logPrefix))
	h.respondTooManyLoginAttempts(ctx, logId, ttl)
	return true
}

func (h *HandlerUser) handleLoginFailure(ctx *gin.Context, logId uuid.UUID, logPrefix, normalizedIdentifier, loginIdentifier string, err error) {
	logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.LoginUser; ERROR: %s;", logPrefix, err))
	if !errors.Is(err, gorm.ErrRecordNotFound) && err.Error() != messages.ErrHashPassword {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Login failed due to internal error",
			ErrorMessage: err.Error(),
			AfterData:    map[string]any{"identifier": normalizedIdentifier},
		})
		ctx.JSON(http.StatusInternalServerError, response.InternalServerError(logId))
		return
	}

	if h.LoginLimiter != nil {
		blocked, ttl, limiterErr := h.LoginLimiter.RegisterFailure(ctx.Request.Context(), loginIdentifier)
		if limiterErr != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.RegisterFailure error: %v", logPrefix, limiterErr))
		}
		if blocked {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:   domainaudit.ActionLogin,
				Resource: "auth",
				Status:   domainaudit.StatusFailed,
				Message:  "Login blocked after repeated failures",
				AfterData: map[string]any{
					"identifier": normalizedIdentifier,
				},
			})
			logger.WriteLogWithContext(ctx, logger.LogLevelWarn, fmt.Sprintf("%s; Account temporarily locked after repeated failures", logPrefix))
			h.respondTooManyLoginAttempts(ctx, logId, ttl)
			return
		}
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogin,
		Resource: "auth",
		Status:   domainaudit.StatusFailed,
		Message:  "Login failed due to invalid credentials",
		AfterData: map[string]any{
			"identifier": normalizedIdentifier,
		},
	})
	res := response.Response(http.StatusBadRequest, messages.InvalidCred, logId, nil)
	res.Error = response.Errors{Code: http.StatusBadRequest, Message: messages.MsgCredential}
	ctx.JSON(http.StatusBadRequest, res)
}

func (h *HandlerUser) resetLoginLimiter(ctx *gin.Context, logPrefix, loginIdentifier string) {
	if h.LoginLimiter == nil {
		return
	}
	if err := h.LoginLimiter.Reset(ctx.Request.Context(), loginIdentifier); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.Reset error: %v", logPrefix, err))
	}
}

func (h *HandlerUser) createLoginSession(ctx *gin.Context, reqCtx context.Context, user *domainuser.Users, userErr error, token, refreshToken, logPrefix string) {
	if h.SessionSvc == nil || userErr != nil || refreshToken == "" {
		return
	}
	session, err := h.SessionSvc.CreateSession(reqCtx, user, token, refreshToken, domainsession.RequestMeta{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Failed to create session: %v", logPrefix, err))
		return
	}
	logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Session created: %s", logPrefix, session.SessionID))
}

func (h *HandlerUser) forgotPasswordByEmail(ctx *gin.Context, req dto.ForgotPasswordRequest, logId uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := response.Response(http.StatusServiceUnavailable, messages.MsgSomethingWrong, logId, nil)
		res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: passwordResetEmailNotConfiguredMessage}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	reqCtx := ctx.Request.Context()
	normalizedEmail := utils.SanitizeEmail(req.Email)
	if data, err := h.Service.GetUserByEmail(reqCtx, normalizedEmail); err == nil && data.Id != "" {
		appName := utils.FirstNonEmptyString(utils.GetEnv("AUTH_EMAIL_APP_NAME", ""), utils.GetEnv("APP_NAME", "STARTER-KIT"))
		if err := h.ResetService.RequestReset(reqCtx, normalizedEmail, appName); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
				Message: "Failed to request password reset email", ErrorMessage: err.Error(),
				AfterData: map[string]any{"email": normalizedEmail},
			})
			if throttle, ok := errors.AsType[*servicereset.ThrottleError](err); ok {
				h.respondThrottle(ctx, logId, throttle.RetryAfter, "Password reset request is throttled. Please try again later.")
				return
			}
			statusCode := http.StatusInternalServerError
			message := "Failed to send password reset email. Please contact support with the log ID."
			if errors.Is(err, servicereset.ErrResetNotConfigured) || errors.Is(err, servicereset.ErrResetDeliveryFailed) {
				statusCode = http.StatusServiceUnavailable
				message = "Password reset email service is temporarily unavailable."
			}
			res := response.Response(statusCode, messages.MsgSomethingWrong, logId, nil)
			res.Error = response.Errors{Code: statusCode, Message: message}
			ctx.JSON(statusCode, res)
			return
		}
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Requested password reset email", AfterData: map[string]any{"email": normalizedEmail},
	})
	res := response.Response(http.StatusOK, "Password reset instructions sent to your email", logId, map[string]any{
		"cooldown": int(config.LoadPasswordResetConfig().Cooldown.Seconds()),
	})
	logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Password reset instructions sent to email: %s", logPrefix, normalizedEmail))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) resetPasswordByEmail(ctx *gin.Context, req dto.ResetPasswordRequest, logId uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := response.Response(http.StatusServiceUnavailable, messages.MsgSomethingWrong, logId, nil)
		res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: passwordResetEmailNotConfiguredMessage}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}
	reqCtx := ctx.Request.Context()
	email, err := h.ResetService.VerifyReset(reqCtx, req.Token)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to verify password reset token", ErrorMessage: err.Error(),
		})
		statusCode := http.StatusBadRequest
		message := "invalid or expired reset token"
		if errors.Is(err, servicereset.ErrResetNotConfigured) {
			statusCode = http.StatusServiceUnavailable
			message = passwordResetEmailNotConfiguredMessage
		}
		res := response.Response(statusCode, messages.MsgSomethingWrong, logId, nil)
		res.Error = response.Errors{Code: statusCode, Message: message}
		ctx.JSON(statusCode, res)
		return
	}

	userID := ""
	if h.SessionSvc != nil {
		user, err := h.Service.GetUserByEmail(reqCtx, email)
		if err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
				Message: "Failed to load user for password reset", ErrorMessage: err.Error(),
				AfterData: map[string]any{"email": email},
			})
			statusCode, res := userMutationErrorResponse(logId, err)
			ctx.JSON(statusCode, res)
			return
		}
		userID = user.Id
	}
	if err := h.Service.ResetPasswordByEmail(reqCtx, email, req.NewPassword); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to reset password", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	if err := h.revokePasswordResetSessions(reqCtx, userID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to revoke sessions after password reset", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; SessionSvc.DestroyAllUserSessions; ERROR: %s;", logPrefix, err))
		ctx.JSON(http.StatusInternalServerError, response.InternalServerError(logId))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Reset password success", AfterData: map[string]any{"email": email},
	})
	ctx.JSON(http.StatusOK, response.Response(http.StatusOK, "Password reset successfully", logId, nil))
}

func (h *HandlerUser) isRuntimeConfigEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	if h.AppConfigService == nil {
		return fallback, nil
	}
	return h.AppConfigService.IsEnabled(ctx, configKey, fallback)
}

func buildAuthTokenResponse(accessToken, refreshToken string) map[string]any {
	data := map[string]any{
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

func userMutationErrorResponse(logId uuid.UUID, err error) (int, *response.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, response.ErrorResponse(http.StatusNotFound, messages.MsgNotFound, logId, userNotFoundMessage)
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.MsgExists, logId, "email or phone already exists")
	}

	errMsg := err.Error()
	switch {
	case errMsg == userNotFoundMessage:
		return http.StatusNotFound, response.ErrorResponse(http.StatusNotFound, messages.MsgNotFound, logId, userNotFoundMessage)
	case errMsg == "invalid or expired token":
		return http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.MsgSomethingWrong, logId, "invalid or expired reset token")
	case strings.HasPrefix(errMsg, "access denied:"),
		strings.Contains(errMsg, "superadmin"):
		return http.StatusForbidden, response.Forbidden(logId, messages.AccessDenied)
	case strings.Contains(errMsg, "already exists"):
		return http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.MsgExists, logId, errMsg)
	case strings.HasPrefix(errMsg, "invalid role:"),
		strings.HasPrefix(errMsg, "password must "),
		strings.HasPrefix(errMsg, "new password must "):
		return http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.MsgSomethingWrong, logId, errMsg)
	default:
		return http.StatusInternalServerError, response.InternalServerError(logId)
	}
}

func impersonationErrorResponse(logId uuid.UUID, err error) (int, *response.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, response.ErrorResponse(http.StatusNotFound, messages.MsgNotFound, logId, userNotFoundMessage)
	}

	errMsg := err.Error()
	switch {
	case strings.HasPrefix(errMsg, "cannot impersonate"):
		return http.StatusForbidden, response.Forbidden(logId, messages.AccessDenied)
	case strings.HasPrefix(errMsg, "cannot start"),
		strings.HasPrefix(errMsg, "target user id"),
		strings.HasPrefix(errMsg, "original user id"),
		strings.HasPrefix(errMsg, "current session"):
		return http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.MsgSomethingWrong, logId, errMsg)
	default:
		return http.StatusInternalServerError, response.InternalServerError(logId)
	}
}

func buildImpersonationClaimsOverrideFromClaims(claims map[string]any) *utils.AppClaims {
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
