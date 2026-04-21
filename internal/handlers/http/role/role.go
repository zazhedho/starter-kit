package handlerrole

import (
	"fmt"
	"net/http"
	"reflect"
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/internal/dto"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	interfacerole "starter-kit/internal/interfaces/role"
	"starter-kit/pkg/filter"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
)

type RoleHandler struct {
	Service      interfacerole.ServiceRoleInterface
	AuditService interfaceaudit.ServiceAuditInterface
}

func NewRoleHandler(s interfacerole.ServiceRoleInterface, auditService interfaceaudit.ServiceAuditInterface) *RoleHandler {
	return &RoleHandler{
		Service:      s,
		AuditService: auditService,
	}
}

func (h *RoleHandler) Create(ctx *gin.Context) {
	var req dto.RoleCreate
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Create]"
	reqCtx := ctx.Request.Context()

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	data, err := h.Service.Create(reqCtx, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "role",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create role",
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Create; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "role",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created role",
		AfterData:  data,
	})

	res := response.Response(http.StatusCreated, "Role created successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *RoleHandler) GetByID(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][GetByID]"
	reqCtx := ctx.Request.Context()

	data, err := h.Service.GetByIDWithDetails(reqCtx, id)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetByIDWithDetails; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusNotFound, "Role not found", logId, nil)
		res.Error = response.Errors{Code: http.StatusNotFound, Message: "role not found"}
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := response.Response(http.StatusOK, "Get role successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *RoleHandler) GetAll(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][GetAll]"
	reqCtx := ctx.Request.Context()

	params, err := filter.GetBaseParams(ctx, "name", "asc", 10)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "invalid query parameters"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, total, err := h.Service.GetAll(reqCtx, params)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := response.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *RoleHandler) Update(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dto.RoleUpdate
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Update]"
	reqCtx := ctx.Request.Context()

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	before, _ := h.Service.GetByID(reqCtx, id)
	data, err := h.Service.Update(reqCtx, id, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "role",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update role",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "role",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated role",
		BeforeData: before,
		AfterData:  data,
	})

	res := response.Response(http.StatusOK, "Role updated successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *RoleHandler) Delete(ctx *gin.Context) {
	id := ctx.Param("id")
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][Delete]"
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetByID(reqCtx, id)

	if err := h.Service.Delete(reqCtx, id); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "role",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete role",
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Delete; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "role",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted role",
		BeforeData: before,
	})

	res := response.Response(http.StatusOK, "Role deleted successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Response: Role deleted", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *RoleHandler) AssignPermissions(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dto.AssignPermissions
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][AssignPermissions]"
	reqCtx := ctx.Request.Context()

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	beforeIDs, _ := h.Service.GetRolePermissions(reqCtx, id)
	if err := h.Service.AssignPermissions(reqCtx, id, req); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionAssign,
			Resource:     "role_permissions",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to assign permissions to role",
			ErrorMessage: err.Error(),
			BeforeData: map[string]interface{}{
				"permission_ids": beforeIDs,
			},
			AfterData: req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.AssignPermissions; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionAssign,
		Resource:   "role_permissions",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Assigned permissions to role",
		BeforeData: map[string]interface{}{
			"permission_ids": beforeIDs,
		},
		AfterData: req,
	})

	res := response.Response(http.StatusOK, "Permissions assigned successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Permissions assigned", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *RoleHandler) AssignMenus(ctx *gin.Context) {
	id := ctx.Param("id")
	var req dto.AssignMenus
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[RoleHandler][AssignMenus]"
	reqCtx := ctx.Request.Context()

	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, utils.JsonEncode(req)))

	beforeIDs, _ := h.Service.GetRoleMenus(reqCtx, id)
	if err := h.Service.AssignMenus(reqCtx, id, req); err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionAssign,
			Resource:     "role_menus",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to assign menus to role",
			ErrorMessage: err.Error(),
			BeforeData: map[string]interface{}{
				"menu_ids": beforeIDs,
			},
			AfterData: req,
		})
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.AssignMenus; Error: %+v", logPrefix, err))
		statusCode, res := roleMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionAssign,
		Resource:   "role_menus",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Assigned menus to role",
		BeforeData: map[string]interface{}{
			"menu_ids": beforeIDs,
		},
		AfterData: req,
	})

	res := response.Response(http.StatusOK, "Menus assigned successfully", logId, nil)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Menus assigned", logPrefix))
	ctx.JSON(http.StatusOK, res)
}
