package handleruser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"reflect"
	domainaudit "starter-kit/internal/domain/audit"
	domainsession "starter-kit/internal/domain/session"
	domainuser "starter-kit/internal/domain/user"
	"starter-kit/internal/dto"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	interfaceauth "starter-kit/internal/interfaces/auth"
	interfaceotp "starter-kit/internal/interfaces/otp"
	interfacereset "starter-kit/internal/interfaces/reset"
	interfacesession "starter-kit/internal/interfaces/session"
	interfaceuser "starter-kit/internal/interfaces/user"
	serviceotp "starter-kit/internal/services/otp"
	servicereset "starter-kit/internal/services/reset"
	serviceuser "starter-kit/internal/services/user"
	"starter-kit/pkg/filter"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/pkg/security"
	"starter-kit/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HandlerUser struct {
	Service          interfaceuser.ServiceUserInterface
	BlacklistRepo    interfaceauth.RepoAuthInterface
	SessionSvc       interfacesession.ServiceSessionInterface
	LoginLimiter     security.LoginLimiter
	AuditService     interfaceaudit.ServiceAuditInterface
	AppConfigService interfaceappconfig.ServiceAppConfigInterface
	OTPService       interfaceotp.ServiceOTPInterface
	ResetService     interfacereset.ServicePasswordResetInterface
}

func NewUserHandler(
	s interfaceuser.ServiceUserInterface,
	blacklistRepo interfaceauth.RepoAuthInterface,
	sessionSvc interfacesession.ServiceSessionInterface,
	limiter security.LoginLimiter,
	auditService interfaceaudit.ServiceAuditInterface,
	appConfigService interfaceappconfig.ServiceAppConfigInterface,
	otpService interfaceotp.ServiceOTPInterface,
	resetService interfacereset.ServicePasswordResetInterface,
) *HandlerUser {
	return &HandlerUser{
		Service:          s,
		BlacklistRepo:    blacklistRepo,
		SessionSvc:       sessionSvc,
		LoginLimiter:     limiter,
		AuditService:     auditService,
		AppConfigService: appConfigService,
		OTPService:       otpService,
		ResetService:     resetService,
	}
}

func (h *HandlerUser) Register(ctx *gin.Context) {
	var req dto.UserRegister
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Register]"

	registerEnabled, err := h.isRuntimeConfigEnabled(publicRegistrationConfigKey(), true)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if !registerEnabled {
		res := response.Forbidden(logId, "Public registration is currently disabled.")
		ctx.JSON(http.StatusForbidden, res)
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))

		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	otpEnabled, err := h.isRuntimeConfigEnabled(registerOTPConfigKey(), false)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if otpEnabled {
		if strings.TrimSpace(req.OTPCode) == "" {
			res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
			res.Error = response.Errors{Code: http.StatusBadRequest, Message: "otp_code is required"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
		if h.OTPService == nil {
			res := response.Response(http.StatusServiceUnavailable, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: "registration OTP service is not configured"}
			ctx.JSON(http.StatusServiceUnavailable, res)
			return
		}
		if err := h.OTPService.VerifyRegisterOTP(ctx.Request.Context(), req.Email, req.OTPCode); err != nil {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionCreate,
				Resource:     "user",
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to verify registration OTP",
				ErrorMessage: err.Error(),
				AfterData: map[string]interface{}{
					"email": req.Email,
				},
			})
			statusCode := http.StatusBadRequest
			message := "invalid or expired OTP"
			if errors.Is(err, serviceotp.ErrOTPTooManyAttempt) {
				message = "too many OTP attempts"
			}
			if errors.Is(err, serviceotp.ErrOTPNotConfigured) {
				statusCode = http.StatusServiceUnavailable
				message = "registration OTP service is not configured"
			}
			res := response.Response(statusCode, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: statusCode, Message: message}
			ctx.JSON(statusCode, res)
			return
		}
		req.EmailVerified = true
	}

	data, err := h.Service.RegisterUser(req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to register user",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"name":  req.Name,
				"email": req.Email,
				"phone": req.Phone,
			},
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.RegisterUser; Error: %+v", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: data.Id,
		ActorRole:   data.Role,
		Action:      domainaudit.ActionCreate,
		Resource:    "user",
		ResourceID:  data.Id,
		Status:      domainaudit.StatusSuccess,
		Message:     "Registered user",
		AfterData: map[string]interface{}{
			"id":    data.Id,
			"name":  data.Name,
			"email": data.Email,
			"phone": data.Phone,
			"role":  data.Role,
		},
	})

	res := response.Response(http.StatusCreated, "User registered successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *HandlerUser) GetRegisterStatus(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetRegisterStatus]"

	registerEnabled, err := h.isRuntimeConfigEnabled(publicRegistrationConfigKey(), true)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get register status successfully", logId, map[string]interface{}{
		"enabled": registerEnabled,
	})
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) SendRegisterOTP(ctx *gin.Context) {
	var req dto.SendRegisterOTPRequest
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][SendRegisterOTP]"

	registerEnabled, err := h.isRuntimeConfigEnabled(publicRegistrationConfigKey(), true)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if !registerEnabled {
		res := response.Forbidden(logId, "Public registration is currently disabled.")
		ctx.JSON(http.StatusForbidden, res)
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	otpEnabled, err := h.isRuntimeConfigEnabled(registerOTPConfigKey(), false)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if !otpEnabled {
		res := response.Response(http.StatusBadRequest, messages.MsgFail, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "registration OTP is disabled"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	if h.OTPService == nil {
		res := response.Response(http.StatusServiceUnavailable, messages.MsgFail, logId, nil)
		res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: "registration OTP service is not configured"}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	normalizedEmail := utils.SanitizeEmail(req.Email)
	if data, err := h.Service.GetUserByEmail(normalizedEmail); err == nil && data.Id != "" {
		res := response.Response(http.StatusBadRequest, messages.MsgExists, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "email already exists"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if err := h.OTPService.SendRegisterOTP(ctx.Request.Context(), normalizedEmail, authEmailAppName()); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user_registration_otp",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to send registration OTP",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"email": normalizedEmail,
			},
		})
		if throttle, ok := errors.AsType[*serviceotp.ThrottleError](err); ok {
			h.respondThrottle(ctx, logId, throttle.RetryAfter, "OTP request is throttled. Please try again later.")
			return
		}
		if errors.Is(err, serviceotp.ErrOTPNotConfigured) || errors.Is(err, serviceotp.ErrOTPDeliveryFailed) {
			statusCode := http.StatusServiceUnavailable
			res := response.ErrorResponse(statusCode, messages.MsgFail, logId, "Registration OTP service is temporarily unavailable.")
			ctx.JSON(statusCode, res)
			return
		}

		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionCreate,
		Resource: "user_registration_otp",
		Status:   domainaudit.StatusSuccess,
		Message:  "Sent registration OTP",
		AfterData: map[string]interface{}{
			"email": normalizedEmail,
		},
	})
	res := response.Response(http.StatusOK, "Registration OTP sent successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Registration OTP sent successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) AdminCreateUser(ctx *gin.Context) {
	var req dto.AdminCreateUser
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][AdminCreateUser]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	// Get creator's role from auth data
	authData := utils.GetAuthData(ctx)
	if authData == nil {
		res := response.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}
	creatorRole := authData["role"].(string)
	creatorUserID := utils.InterfaceString(authData["user_id"])

	data, err := h.Service.AdminCreateUser(req, creatorUserID, creatorRole)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create user",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"name":  req.Name,
				"email": req.Email,
				"phone": req.Phone,
				"role":  req.Role,
			},
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.AdminCreateUser; Error: %+v", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "user",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created user by admin",
		AfterData: map[string]interface{}{
			"id":    data.Id,
			"name":  data.Name,
			"email": data.Email,
			"phone": data.Phone,
			"role":  data.Role,
		},
	})

	res := response.Response(http.StatusCreated, "User created successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *HandlerUser) Login(ctx *gin.Context) {
	var req dto.Login
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserController][Login]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))

		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	rawIdentifier := strings.TrimSpace(req.Identifier)
	if rawIdentifier == "" {
		rawIdentifier = strings.TrimSpace(req.Email)
	}
	if rawIdentifier == "" {
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "identifier or email is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	var normalizedIdentifier string
	if strings.Contains(rawIdentifier, "@") {
		normalizedIdentifier = utils.SanitizeEmail(rawIdentifier)
		if _, err := mail.ParseAddress(normalizedIdentifier); err != nil {
			res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
			res.Error = response.Errors{Code: http.StatusBadRequest, Message: "identifier must be a valid email or phone number"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
	} else {
		normalizedIdentifier = utils.NormalizePhoneTo62(rawIdentifier)
		if len(normalizedIdentifier) < 9 || len(normalizedIdentifier) > 15 {
			res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
			res.Error = response.Errors{Code: http.StatusBadRequest, Message: "identifier must be a valid email or phone number"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
	}

	loginIdentifier := fmt.Sprintf("%s:%s", ctx.ClientIP(), normalizedIdentifier)
	if h.LoginLimiter != nil {
		blocked, ttl, limiterErr := h.LoginLimiter.IsBlocked(ctx.Request.Context(), loginIdentifier)
		if limiterErr != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.IsBlocked error: %v", logPrefix, limiterErr))
		} else if blocked {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				Action:   domainaudit.ActionLogin,
				Resource: "auth",
				Status:   domainaudit.StatusFailed,
				Message:  "Login blocked due to too many attempts",
				AfterData: map[string]interface{}{
					"identifier": normalizedIdentifier,
				},
			})
			logger.WriteLogWithContext(ctx, logger.LogLevelWarn, fmt.Sprintf("%s; Too many attempts", logPrefix))
			h.respondTooManyLoginAttempts(ctx, logId, ttl)
			return
		}
	}

	token, err := h.Service.LoginUser(req, logId.String(), dto.LoginMetadata{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.LoginUser; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) || err.Error() == messages.ErrHashPassword {
			if h.LoginLimiter != nil {
				blocked, ttl, limiterErr := h.LoginLimiter.RegisterFailure(ctx.Request.Context(), loginIdentifier)
				if limiterErr != nil {
					logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.RegisterFailure error: %v", logPrefix, limiterErr))
				}
				if blocked {
					h.writeAudit(ctx, domainaudit.AuditEvent{
						Action:   domainaudit.ActionLogin,
						Resource: "auth",
						Status:   domainaudit.StatusFailed,
						Message:  "Login blocked after repeated failures",
						AfterData: map[string]interface{}{
							"identifier": normalizedIdentifier,
						},
					})
					logger.WriteLogWithContext(ctx, logger.LogLevelWarn, fmt.Sprintf("%s; Account temporarily locked after repeated failures", logPrefix))
					h.respondTooManyLoginAttempts(ctx, logId, ttl)
					return
				}
			}

			h.writeAudit(ctx, domainaudit.AuditEvent{
				Action:   domainaudit.ActionLogin,
				Resource: "auth",
				Status:   domainaudit.StatusFailed,
				Message:  "Login failed due to invalid credentials",
				AfterData: map[string]interface{}{
					"identifier": normalizedIdentifier,
				},
			})
			res := response.Response(http.StatusBadRequest, messages.InvalidCred, logId, nil)
			res.Error = response.Errors{Code: http.StatusBadRequest, Message: messages.MsgCredential}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}

		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Login failed due to internal error",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"identifier": normalizedIdentifier,
			},
		})
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	var (
		loggedInUser domainuser.Users
		userErr      error
	)
	if strings.Contains(normalizedIdentifier, "@") {
		loggedInUser, userErr = h.Service.GetUserByEmail(normalizedIdentifier)
	} else {
		loggedInUser, userErr = h.Service.GetUserByPhone(normalizedIdentifier)
	}
	loginUserID := ""
	if userErr == nil {
		loginUserID = loggedInUser.Id
	}

	refreshToken := ""
	if userErr == nil {
		refreshToken, err = utils.GenerateRefreshJwt(&loggedInUser, logId.String(), nil)
		if err != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GenerateRefreshJwt; ERROR: %s;", logPrefix, err))
			res := response.InternalServerError(logId)
			ctx.JSON(http.StatusInternalServerError, res)
			return
		}
	}

	if h.LoginLimiter != nil {
		if err := h.LoginLimiter.Reset(ctx.Request.Context(), loginIdentifier); err != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; LoginLimiter.Reset error: %v", logPrefix, err))
		}
	}

	// Create session if Redis is available
	if h.SessionSvc != nil && userErr == nil && refreshToken != "" {
		session, errSession := h.SessionSvc.CreateSession(context.Background(), &loggedInUser, token, refreshToken, domainsession.RequestMeta{
			IP:        ctx.ClientIP(),
			UserAgent: ctx.GetHeader("User-Agent"),
		})
		if errSession != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Failed to create session: %v", logPrefix, errSession))
		} else {
			logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Session created: %s", logPrefix, session.SessionID))
		}
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: loginUserID,
		ActorRole:   loggedInUser.Role,
		Action:      domainaudit.ActionLogin,
		Resource:    "auth",
		ResourceID:  loginUserID,
		Status:      domainaudit.StatusSuccess,
		Message:     "Login success",
		AfterData: map[string]interface{}{
			"identifier": normalizedIdentifier,
		},
	})

	res := response.Response(http.StatusOK, "success", logId, buildAuthTokenResponse(token, refreshToken))
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(token)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) GoogleLogin(ctx *gin.Context) {
	var req dto.GoogleLogin
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GoogleLogin]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	registerEnabled, err := h.isRuntimeConfigEnabled(publicRegistrationConfigKey(), true)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	user, isNewUser, err := h.Service.LoginWithGoogle(req, dto.LoginMetadata{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	}, registerEnabled)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Google login failed",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"provider": "google",
			},
		})

		statusCode := http.StatusBadRequest
		switch {
		case errors.Is(err, serviceuser.ErrGoogleNotConfigured):
			statusCode = http.StatusServiceUnavailable
		case errors.Is(err, serviceuser.ErrGoogleTokenInvalid), errors.Is(err, serviceuser.ErrGoogleEmailMissing):
			statusCode = http.StatusUnauthorized
		case errors.Is(err, serviceuser.ErrPublicRegistrationDisabled):
			statusCode = http.StatusForbidden
		}

		res := response.InternalServerError(logId)
		switch {
		case errors.Is(err, serviceuser.ErrGoogleNotConfigured):
			res = response.ErrorResponse(statusCode, messages.MsgFail, logId, "Google login is not configured.")
		case errors.Is(err, serviceuser.ErrGoogleTokenInvalid):
			res = response.ErrorResponse(statusCode, messages.MsgFail, logId, "Invalid Google token.")
		case errors.Is(err, serviceuser.ErrGoogleEmailMissing):
			res = response.ErrorResponse(statusCode, messages.MsgFail, logId, "Google account email is not available.")
		case errors.Is(err, serviceuser.ErrPublicRegistrationDisabled):
			res = response.Forbidden(logId, "Public registration is currently disabled.")
		}
		ctx.JSON(statusCode, res)
		return
	}

	accessToken, err := utils.GenerateJwt(&user, logId.String())
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GenerateJwt; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	refreshToken, err := utils.GenerateRefreshJwt(&user, logId.String(), nil)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GenerateRefreshJwt; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	if h.SessionSvc != nil {
		session, errSession := h.SessionSvc.CreateSession(context.Background(), &user, accessToken, refreshToken, domainsession.RequestMeta{
			IP:        ctx.ClientIP(),
			UserAgent: ctx.GetHeader("User-Agent"),
		})
		if errSession != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Failed to create session: %v", logPrefix, errSession))
		} else {
			logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Session created: %s", logPrefix, session.SessionID))
		}
	}

	successMessage := "Google login success"
	if isNewUser {
		successMessage = "Google registration success"
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: user.Id,
		ActorRole:   user.Role,
		Action:      domainaudit.ActionLogin,
		Resource:    "auth",
		ResourceID:  user.Id,
		Status:      domainaudit.StatusSuccess,
		Message:     successMessage,
		AfterData: map[string]interface{}{
			"provider":    "google",
			"email":       user.Email,
			"is_new_user": isNewUser,
		},
	})

	data := buildAuthTokenResponse(accessToken, refreshToken)
	data["is_new_user"] = isNewUser
	data["provider"] = "google"

	res := response.Response(http.StatusOK, successMessage, logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; %s; Data: %+v", logPrefix, successMessage, data))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) RefreshToken(ctx *gin.Context) {
	var req dto.RefreshTokenRequest
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][RefreshToken]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	tokenClaims, err := utils.JwtClaim(req.RefreshToken)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to renew login session",
			ErrorMessage: "The refresh token is invalid or expired",
		})
		res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
		res.Error = "invalid or expired refresh token"
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	if !strings.EqualFold(utils.InterfaceString(tokenClaims["token_type"]), "refresh") {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  utils.InterfaceString(tokenClaims["user_id"]),
			ActorRole:    utils.InterfaceString(tokenClaims["role"]),
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to renew login session",
			ErrorMessage: "The provided token is not a refresh token",
		})
		res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
		res.Error = "invalid token type"
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	isBlacklisted, err := h.BlacklistRepo.ExistsByToken(req.RefreshToken)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  utils.InterfaceString(tokenClaims["user_id"]),
			ActorRole:    utils.InterfaceString(tokenClaims["role"]),
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to validate login session renewal",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BlacklistRepo.ExistsByToken; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if isBlacklisted {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  utils.InterfaceString(tokenClaims["user_id"]),
			ActorRole:    utils.InterfaceString(tokenClaims["role"]),
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to renew login session",
			ErrorMessage: "The refresh token has already been revoked",
		})
		res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
		res.Error = "refresh token has been revoked"
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	userID := utils.InterfaceString(tokenClaims["user_id"])
	userRole := utils.InterfaceString(tokenClaims["role"])
	user, err := h.Service.GetUserById(userID)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    userRole,
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			ResourceID:   userID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to renew login session",
			ErrorMessage: "The token owner user account was not found",
		})
		statusCode := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			statusCode = http.StatusNotFound
		}
		res := response.Response(statusCode, messages.MsgFail, logId, nil)
		res.Error = "user not found"
		ctx.JSON(statusCode, res)
		return
	}

	claimsOverride := buildImpersonationClaimsOverrideFromClaims(tokenClaims)
	accessToken, err := utils.GenerateJwtWithClaims(&user, logId.String(), claimsOverride)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    user.Role,
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			ResourceID:   userID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to issue a new access token",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GenerateJwtWithClaims; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	refreshToken, err := utils.GenerateRefreshJwt(&user, logId.String(), claimsOverride)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    user.Role,
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			ResourceID:   userID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to issue a new refresh token",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GenerateRefreshJwt; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	if h.SessionSvc != nil {
		session, sessionErr := h.SessionSvc.GetSessionByRefreshToken(context.Background(), req.RefreshToken)
		if sessionErr != nil {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				ActorUserID:  userID,
				ActorRole:    user.Role,
				Action:       domainaudit.ActionRefresh,
				Resource:     "auth_token",
				ResourceID:   userID,
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to renew login session",
				ErrorMessage: "No active session was found for the refresh token",
			})
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; SessionSvc.GetSessionByRefreshToken; ERROR: %s;", logPrefix, sessionErr))
			res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
			res.Error = "session not found for refresh token"
			ctx.JSON(http.StatusUnauthorized, res)
			return
		}

		refreshExpAt := time.Now().Add(time.Hour * time.Duration(utils.GetEnv("REFRESH_TOKEN_EXP_HOURS", 168)))
		if sessionErr = h.SessionSvc.RotateSessionTokens(context.Background(), session.SessionID, accessToken, refreshToken, refreshExpAt); sessionErr != nil {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				ActorUserID:  userID,
				ActorRole:    user.Role,
				Action:       domainaudit.ActionRefresh,
				Resource:     "auth_token",
				ResourceID:   userID,
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to rotate login session tokens",
				ErrorMessage: sessionErr.Error(),
				Metadata: map[string]interface{}{
					"session_id": session.SessionID,
				},
			})
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; SessionSvc.RotateSessionTokens; ERROR: %s;", logPrefix, sessionErr))
			res := response.InternalServerError(logId)
			ctx.JSON(http.StatusInternalServerError, res)
			return
		}
	}

	if err = h.Service.LogoutUser(req.RefreshToken); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    user.Role,
			Action:       domainaudit.ActionRefresh,
			Resource:     "auth_token",
			ResourceID:   userID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to revoke previous login session token",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.LogoutUser(refresh); ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: userID,
		ActorRole:   user.Role,
		Action:      domainaudit.ActionRefresh,
		Resource:    "auth_token",
		ResourceID:  userID,
		Status:      domainaudit.StatusSuccess,
		Message:     "Renewed login session",
	})

	res := response.Response(http.StatusOK, "Refresh token rotated successfully", logId, buildAuthTokenResponse(accessToken, refreshToken))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) Logout(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserController][Logout]"

	token, ok := ctx.Get("token")
	if !ok {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Logout failed because token missing in context",
			ErrorMessage: "token not found",
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; token not found in context", logPrefix))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	if h.SessionSvc != nil {
		errSession := h.SessionSvc.DestroySessionByToken(context.Background(), token.(string))
		if errSession != nil {
			logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Failed to destroy session: %v", logPrefix, errSession))
		} else {
			logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Session destroyed successfully", logPrefix))
		}
	}

	if err := h.Service.LogoutUser(token.(string)); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Logout failed",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.LogoutUser; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogout,
		Resource: "auth",
		Status:   domainaudit.StatusSuccess,
		Message:  "Logout success",
	})

	res := response.Response(http.StatusOK, "User logged out successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: User logged out successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) GetUserById(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetUserByID]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetUserById(id)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetUserByID; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "success", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) GetUserByAuth(ctx *gin.Context) {
	authData := utils.GetAuthData(ctx)
	userId := utils.InterfaceString(authData["user_id"])
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetUserByAuth]"

	data, err := h.Service.GetUserByAuth(userId)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetUserByAuth; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	if isImpersonated, ok := authData["is_impersonated"].(bool); ok {
		data["is_impersonated"] = isImpersonated
		if isImpersonated {
			data["impersonator"] = map[string]interface{}{
				"user_id":  utils.InterfaceString(authData["original_user_id"]),
				"username": utils.InterfaceString(authData["original_username"]),
				"role":     utils.InterfaceString(authData["original_role"]),
			}
		}
	} else {
		data["is_impersonated"] = false
	}

	res := response.Response(http.StatusOK, "success", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) ImpersonateUser(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ImpersonateUser]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	authData := utils.GetAuthData(ctx)
	currentUserID := utils.InterfaceString(authData["user_id"])
	currentUserName := utils.InterfaceString(authData["username"])
	currentUserRole := utils.InterfaceString(authData["role"])
	alreadyImpersonated, _ := authData["is_impersonated"].(bool)

	token, err := h.Service.ImpersonateUser(id, currentUserID, currentUserName, currentUserRole, alreadyImpersonated, logId.String())
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "user_impersonation",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to impersonate user",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"target_user_id": id,
			},
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.ImpersonateUser; ERROR: %s;", logPrefix, err))

		statusCode, res := impersonationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionLogin,
		Resource:   "user_impersonation",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Started impersonation session",
		AfterData: map[string]interface{}{
			"target_user_id": id,
		},
		Metadata: map[string]interface{}{
			"impersonation_action": "start",
			"target_user_id":       id,
		},
	})

	res := response.Response(http.StatusOK, "Impersonation started successfully", logId, buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) StopImpersonation(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][StopImpersonation]"

	authData := utils.GetAuthData(ctx)
	currentUserID := utils.InterfaceString(authData["user_id"])
	originalUserID := utils.InterfaceString(authData["original_user_id"])
	isImpersonated, _ := authData["is_impersonated"].(bool)
	if !isImpersonated || originalUserID == "" {
		res := response.Response(http.StatusBadRequest, messages.MsgFail, logId, nil)
		res.Error = "current session is not impersonated"
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	token, err := h.Service.StopImpersonation(originalUserID, currentUserID, logId.String())
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "user_impersonation",
			ResourceID:   originalUserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to stop impersonation",
			ErrorMessage: err.Error(),
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.StopImpersonation; ERROR: %s;", logPrefix, err))

		statusCode, res := impersonationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}

	if tokenString, ok := ctx.Get("token"); ok {
		_ = h.Service.LogoutUser(tokenString.(string))
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionLogout,
		Resource:   "user_impersonation",
		ResourceID: originalUserID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Stopped impersonation session",
		Metadata: map[string]interface{}{
			"impersonation_action": "stop",
			"restored_user_id":     originalUserID,
		},
	})

	res := response.Response(http.StatusOK, "Impersonation stopped successfully", logId, buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) GetAllUsers(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetAllUsers]"

	authData := utils.GetAuthData(ctx)
	currentUserRole := utils.InterfaceString(authData["role"])

	params, _ := filter.GetBaseParams(ctx, "updated_at", "desc", 10)
	params.Filters = filter.WhitelistFilter(params.Filters, []string{"role"})

	users, totalData, err := h.Service.GetAllUsers(params, currentUserRole)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GetAllUsers; ERROR: %+v;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(totalData), params.Page, params.Limit, logId, users)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(users)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) Update(ctx *gin.Context) {
	var req dto.UserUpdate
	authData := utils.GetAuthData(ctx)
	userId := utils.InterfaceString(authData["user_id"])
	role := utils.InterfaceString(authData["role"])
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Update]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))

		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	before, _ := h.Service.GetUserById(userId)
	data, err := h.Service.Update(userId, userId, role, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user",
			ResourceID:   userId,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update user profile",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Update; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated user profile",
		BeforeData: before,
		AfterData:  data,
	})

	res := response.Response(http.StatusOK, "User updated successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) UpdateUserById(ctx *gin.Context) {
	var req dto.UserUpdate
	authData := utils.GetAuthData(ctx)
	currentUserID := utils.InterfaceString(authData["user_id"])
	role := utils.InterfaceString(authData["role"])
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][UpdateUserById]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))

		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	before, _ := h.Service.GetUserById(id)
	data, err := h.Service.Update(id, currentUserID, role, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update user by ID",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Update; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated user by ID",
		BeforeData: before,
		AfterData:  data,
	})

	res := response.Response(http.StatusOK, "User updated successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) ChangePassword(ctx *gin.Context) {
	var req dto.ChangePassword
	authData := utils.GetAuthData(ctx)
	userId := utils.InterfaceString(authData["user_id"])
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ChangePassword]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))

		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	before, _ := h.Service.GetUserById(userId)
	data, err := h.Service.ChangePassword(userId, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password",
			ResourceID:   userId,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to change password",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.ChangePassword; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		if err.Error() == messages.ErrHashPassword {
			res := response.Response(http.StatusBadRequest, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: http.StatusBadRequest, Message: "current password is incorrect"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}

		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user_password",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Changed user password",
		BeforeData: before,
		AfterData: map[string]interface{}{
			"user_id": data.Id,
		},
	})

	res := response.Response(http.StatusOK, "User password changed successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) ForgotPassword(ctx *gin.Context) {
	var req dto.ForgotPasswordRequest
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ForgotPassword]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	emailResetEnabled, err := h.isRuntimeConfigEnabled(passwordResetEmailConfigKey(), false)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if emailResetEnabled {
		if h.ResetService == nil {
			res := response.Response(http.StatusServiceUnavailable, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: "password reset email service is not configured"}
			ctx.JSON(http.StatusServiceUnavailable, res)
			return
		}

		normalizedEmail := utils.SanitizeEmail(req.Email)
		if data, err := h.Service.GetUserByEmail(normalizedEmail); err == nil && data.Id != "" {
			if err := h.ResetService.RequestReset(ctx.Request.Context(), normalizedEmail, authEmailAppName()); err != nil {
				h.writeAudit(ctx, domainaudit.AuditEvent{
					Action:       domainaudit.ActionUpdate,
					Resource:     "user_password_reset",
					Status:       domainaudit.StatusFailed,
					Message:      "Failed to request password reset email",
					ErrorMessage: err.Error(),
					AfterData: map[string]interface{}{
						"email": normalizedEmail,
					},
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
				res := response.Response(statusCode, messages.MsgFail, logId, nil)
				res.Error = response.Errors{Code: statusCode, Message: message}
				ctx.JSON(statusCode, res)
				return
			}
		}

		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:   domainaudit.ActionUpdate,
			Resource: "user_password_reset",
			Status:   domainaudit.StatusSuccess,
			Message:  "Requested password reset email",
			AfterData: map[string]interface{}{
				"email": normalizedEmail,
			},
		})
		res := response.Response(http.StatusOK, "Password reset instructions sent to your email", logId, nil)
		logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("%s; Password reset instructions sent to email: %s", logPrefix, normalizedEmail))
		ctx.JSON(http.StatusOK, res)
		return
	}

	token, err := h.Service.ForgotPassword(req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password_reset",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to request password reset",
			ErrorMessage: err.Error(),
			AfterData: map[string]interface{}{
				"email": req.Email,
			},
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.ForgotPassword; ERROR: %s;", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionUpdate,
		Resource: "user_password_reset",
		Status:   domainaudit.StatusSuccess,
		Message:  "Requested password reset",
		AfterData: map[string]interface{}{
			"email": req.Email,
		},
	})

	logger.WriteLogWithContext(ctx, logger.LogLevelInfo, fmt.Sprintf("MOCK EMAIL SENT: Reset Token for %s: %s", req.Email, token))

	res := response.Response(http.StatusOK, "Password reset instructions sent to your email", logId, token)
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) ResetPassword(ctx *gin.Context) {
	var req dto.ResetPasswordRequest
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ResetPassword]"

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	emailResetEnabled, err := h.isRuntimeConfigEnabled(passwordResetEmailConfigKey(), false)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Config check ERROR: %s;", logPrefix, err.Error()))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	if emailResetEnabled {
		if h.ResetService == nil {
			res := response.Response(http.StatusServiceUnavailable, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: http.StatusServiceUnavailable, Message: "password reset email service is not configured"}
			ctx.JSON(http.StatusServiceUnavailable, res)
			return
		}

		email, err := h.ResetService.VerifyReset(ctx.Request.Context(), req.Token)
		if err != nil {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionUpdate,
				Resource:     "user_password_reset",
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to verify password reset token",
				ErrorMessage: err.Error(),
			})
			statusCode := http.StatusBadRequest
			message := "invalid or expired reset token"
			if errors.Is(err, servicereset.ErrResetNotConfigured) {
				statusCode = http.StatusServiceUnavailable
				message = "password reset email service is not configured"
			}
			res := response.Response(statusCode, messages.MsgFail, logId, nil)
			res.Error = response.Errors{Code: statusCode, Message: message}
			ctx.JSON(statusCode, res)
			return
		}
		if err := h.Service.ResetPasswordByEmail(email, req.NewPassword); err != nil {
			h.writeAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionUpdate,
				Resource:     "user_password_reset",
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to reset password",
				ErrorMessage: err.Error(),
				AfterData: map[string]interface{}{
					"email": email,
				},
			})
			statusCode, res := userMutationErrorResponse(logId, err)
			ctx.JSON(statusCode, res)
			return
		}

		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:   domainaudit.ActionUpdate,
			Resource: "user_password_reset",
			Status:   domainaudit.StatusSuccess,
			Message:  "Reset password success",
			AfterData: map[string]interface{}{
				"email": email,
			},
		})
		res := response.Response(http.StatusOK, "Password reset successfully", logId, nil)
		ctx.JSON(http.StatusOK, res)
		return
	}

	if err := h.Service.ResetPassword(req); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password_reset",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to reset password",
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.ResetPassword; ERROR: %s;", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionUpdate,
		Resource: "user_password_reset",
		Status:   domainaudit.StatusSuccess,
		Message:  "Reset password success",
		AfterData: map[string]interface{}{
			"token": req.Token,
		},
	})

	res := response.Response(http.StatusOK, "Password reset successfully", logId, nil)
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) Delete(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Delete]"
	authData := utils.GetAuthData(ctx)
	userId := utils.InterfaceString(authData["user_id"])
	before, _ := h.Service.GetUserById(userId)

	if err := h.Service.Delete(userId); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "user",
			ResourceID:   userId,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete own user",
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Delete; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "user",
		ResourceID: userId,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted own user",
		BeforeData: before,
	})

	res := response.Response(http.StatusOK, "User deleted successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: User deleted successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) DeleteUserById(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[UserHandler][DeleteUserById]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}
	before, _ := h.Service.GetUserById(id)

	if err := h.Service.Delete(id); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "user",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete user by ID",
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Delete; ERROR: %s;", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.MsgNotFound, logId, nil)
			res.Error = response.Errors{Code: http.StatusNotFound, Message: "user not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "user",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted user by ID",
		BeforeData: before,
	})

	res := response.Response(http.StatusOK, "User deleted successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: User deleted successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}
