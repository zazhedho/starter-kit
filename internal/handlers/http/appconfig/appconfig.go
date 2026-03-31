package handlerappconfig

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/internal/dto"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	"starter-kit/pkg/filter"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AppConfigHandler struct {
	Service      interfaceappconfig.ServiceAppConfigInterface
	AuditService interfaceaudit.ServiceAuditInterface
}

func NewAppConfigHandler(s interfaceappconfig.ServiceAppConfigInterface, auditService interfaceaudit.ServiceAuditInterface) *AppConfigHandler {
	return &AppConfigHandler{
		Service:      s,
		AuditService: auditService,
	}
}

func (h *AppConfigHandler) GetAll(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetAll]"

	params, err := filter.GetBaseParams(ctx, "category", "asc", 50)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; GetBaseParams; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	params.Filters = filter.WhitelistStringFilter(params.Filters, []string{"category"})

	data, total, err := h.Service.GetAll(params)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetAll; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *AppConfigHandler) GetByID(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][GetByID]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetByID(id)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetByID; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusNotFound, "Configuration not found", logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	res := response.Response(http.StatusOK, "Get configuration successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *AppConfigHandler) Update(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[AppConfigHandler][Update]"

	id, err := utils.ValidateUUID(ctx, logId)
	if err != nil {
		return
	}

	var req dto.UpdateAppConfig
	if err := ctx.BindJSON(&req); err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; BindJSON ERROR: %s;", logPrefix, err.Error()))
		res := response.Response(http.StatusBadRequest, messages.InvalidRequest, logId, nil)
		res.Error = utils.ValidateError(err, reflect.TypeOf(req), "json")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	before, _ := h.Service.GetByID(id)
	data, err := h.Service.Update(id, req)
	if err != nil {
		h.writeAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "config",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update configuration",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})

		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.Update; Error: %+v", logPrefix, err))
		if errors.Is(err, gorm.ErrRecordNotFound) {
			res := response.Response(http.StatusNotFound, messages.NotFound, logId, nil)
			res.Error = "config data not found"
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.writeAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "config",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated configuration",
		BeforeData: before,
		AfterData:  data,
	})

	res := response.Response(http.StatusOK, "Configuration updated successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}
