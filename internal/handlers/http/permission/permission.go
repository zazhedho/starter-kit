package handlerpermission

import (
	"fmt"
	"net/http"
	"reflect"
	"starter-kit/internal/dto"
	interfacepermission "starter-kit/internal/interfaces/permission"
	"starter-kit/pkg/filter"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
)

type PermissionHandler struct {
	Service interfacepermission.ServicePermissionInterface
}

func NewPermissionHandler(s interfacepermission.ServicePermissionInterface) *PermissionHandler {
	return &PermissionHandler{Service: s}
}

func (h *PermissionHandler) Create(ctx *gin.Context) {
	var req dto.PermissionCreate
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][Create]", logId)

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	data, err := h.Service.Create(req)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.Create; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, err.Error(), logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusCreated, "Permission created successfully", logId, data)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *PermissionHandler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][GetByID]", logId)

	data, err := h.Service.GetByID(id)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusNotFound, "Permission not found", logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := response.Response(http.StatusOK, "Get permission successfully", logId, data)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *PermissionHandler) GetAll(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][GetAll]", logId)

	params, err := filter.GetBaseParams(ctx, "resource", "asc", 10)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, total, err := h.Service.GetAll(params)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *PermissionHandler) Update(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dto.PermissionUpdate
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][Update]", logId)

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	data, err := h.Service.Update(id, req)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, err.Error(), logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Permission updated successfully", logId, data)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *PermissionHandler) Delete(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][Delete]", logId)

	if err := h.Service.Delete(id); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, err.Error(), logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Permission deleted successfully", logId, nil)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: Permission deleted", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *PermissionHandler) GetUserPermissions(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := fmt.Sprintf("[%s][PermissionHandler][GetUserPermissions]", logId)

	userId, exists := ctx.Get("userId")
	if !exists {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; User ID not found in context", logPrefix))

		authData := utils.GetAuthData(ctx)
		if authData != nil {
			if userIdFromAuth := utils.InterfaceString(authData["user_id"]); userIdFromAuth != "" {
				userId = userIdFromAuth
			} else {
				res := response.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
				ctx.JSON(http.StatusUnauthorized, res)
				return
			}
		} else {
			res := response.Response(http.StatusUnauthorized, "Unauthorized", logId, nil)
			ctx.JSON(http.StatusUnauthorized, res)
			return
		}
	}

	data, err := h.Service.GetUserPermissions(userId.(string))
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("%s; Service.GetUserPermissions; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get user permissions successfully", logId, data)
	logger.WriteLog(logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}
