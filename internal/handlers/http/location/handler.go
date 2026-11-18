package location

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

type Handler struct {
	service Service
}

func New(s Service) *Handler {
	return &Handler{service: s}
}

func (h *Handler) GetProvince(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetProvince]"
	reqCtx := ctx.Request.Context()

	data, err := h.service.GetProvince(reqCtx)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetProvince; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get province successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetCity(ctx *gin.Context) {
	h.listByParent(ctx, "GetCity", "province_code", "Get city successfully", h.service.GetCity)
}

func (h *Handler) GetDistrict(ctx *gin.Context) {
	h.listByParent(ctx, "GetDistrict", "city_code", "Get district successfully", h.service.GetDistrict)
}

func (h *Handler) GetVillage(ctx *gin.Context) {
	h.listByParent(ctx, "GetVillage", "district_code", "Get village successfully", h.service.GetVillage)
}

// listByParent serves the lookups that need a parent code in the query string,
// answering 400 when it is missing.
func (h *Handler) listByParent(ctx *gin.Context, method, param, okMessage string, lookup func(context.Context, string) ([]dtolocation.Location, error)) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][" + method + "]"

	code := ctx.Query(param)
	if code == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: param + " is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, err := lookup(ctx.Request.Context(), code)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.%s; Error: %+v", logPrefix, method, err))
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logId))
		return
	}

	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, okMessage, logId, data))
}

func (h *Handler) Sync(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][Sync]"
	reqCtx := ctx.Request.Context()

	var req dtolocation.SyncRequest
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	data, err := h.service.StartSync(reqCtx, req, authkit.ScopeFrom(reqCtx).ActorUserID())
	if err != nil {
		if errors.Is(err, domainlocation.ErrSyncRunning) {
			res := gokit.Response(http.StatusConflict, gokit.MsgSomethingWrong, logId, data)
			res.Error = gokit.Errors{Code: http.StatusConflict, Message: err.Error()}
			ctx.JSON(http.StatusConflict, res)
			return
		}

		if errors.Is(err, domainlocation.ErrInvalidSync) {
			logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Service.StartSync; Error: %+v", logPrefix, err))
			res := gokit.Response(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, nil)
			res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: err.Error()}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}

		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.StartSync; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusAccepted, "Location sync started", logId, data)
	ctx.JSON(http.StatusAccepted, res)
}

func (h *Handler) GetSyncJob(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetSyncJob]"
	reqCtx := ctx.Request.Context()

	jobID := ctx.Param("id")
	if jobID == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "sync job id is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, err := h.service.GetSyncJob(reqCtx, jobID)
	if err != nil {
		if errors.Is(err, domainlocation.ErrNotFound) {
			res := gokit.Response(http.StatusNotFound, gokit.MsgNotFound, logId, nil)
			res.Error = gokit.Errors{Code: http.StatusNotFound, Message: "location sync job not found"}
			ctx.JSON(http.StatusNotFound, res)
			return
		}

		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetSyncJob; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get location sync job successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}
