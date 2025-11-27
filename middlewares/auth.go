package middlewares

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	interfaceauth "starter-kit/internal/interfaces/auth"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Middleware struct {
	BlacklistRepo interfaceauth.RepoAuthInterface
}

func NewMiddleware(blacklistRepo interfaceauth.RepoAuthInterface) *Middleware {
	return &Middleware{
		BlacklistRepo: blacklistRepo,
	}
}

func (m *Middleware) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			err       error
			logId     uuid.UUID
			logPrefix string
		)

		logId = utils.GenerateLogId(ctx)
		logPrefix = fmt.Sprintf("[%s][AuthMiddleware]", logId)

		tokenString, dataJWT, err := utils.JwtClaims(ctx)
		if err != nil {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Invalid Token: %s; Error: %s;", logPrefix, tokenString, err.Error()))
			res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
			res.Error = err.Error()
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}
		logPrefix += fmt.Sprintf("[%s][%s]", utils.InterfaceString(dataJWT["jti"]), utils.InterfaceString(dataJWT["user_id"]))

		_, err = m.BlacklistRepo.GetByToken(tokenString)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; blacklistRepo.GetByToken; Error: %+v", logPrefix, err))
			res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
			res.Error = err.Error()
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Invalid Token: %s; Error: token is blacklisted;", logPrefix, tokenString))
			res := response.Response(http.StatusUnauthorized, messages.MsgFail, logId, nil)
			res.Error = "Please login and try again"
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}

		ctx.Set(utils.CtxKeyAuthData, dataJWT)
		ctx.Set("token", tokenString)
		ctx.Set("userId", utils.InterfaceString(dataJWT["user_id"]))

		ctx.Next()
	}
}

func (m *Middleware) RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logId     uuid.UUID
			logPrefix string
		)

		logId = utils.GenerateLogId(ctx)
		logPrefix = fmt.Sprintf("[%s][RoleMiddleware]", logId)

		authData, exists := ctx.Get(utils.CtxKeyAuthData)
		if !exists {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; AuthData not found", logPrefix))
			res := response.Response(http.StatusForbidden, messages.MsgDenied, logId, nil)
			res.Error = "auth data not found"
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}
		dataJWT := authData.(map[string]interface{})

		userRole, ok := dataJWT["role"].(string)
		if !ok {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; there is no role user", logPrefix))
			res := response.Response(http.StatusForbidden, messages.MsgDenied, logId, nil)
			res.Error = "there is no role user"
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}

		if userRole == utils.RoleSuperAdmin {
			ctx.Next()
			return
		}

		isAllowed := slices.Contains(allowedRoles, userRole)
		if !isAllowed {
			logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; User with role '%s' tried to access a restricted route;", logPrefix, userRole))
			res := response.Response(http.StatusForbidden, messages.MsgDenied, logId, nil)
			res.Error = response.Errors{Code: http.StatusForbidden, Message: messages.AccessDenied}
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}

		ctx.Next()
	}
}
