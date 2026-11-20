package location

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

const msgSyncRunning = "Location sync is already running"

type Handler struct {
	service Service
}

func New(s Service) *Handler {
	return &Handler{service: s}
}

func (h *Handler) GetProvince(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[LocationHandler][GetProvince]"
	reqCtx := ctx.Request.Context()

	data, err := h.service.GetProvince(reqCtx)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetProvince; Error: %+v", logPrefix, err)
		res := gokit.InternalServerError(logID)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get province successfully", logID, data)
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
	logID := gokit.RequestID(ctx)
	logPrefix := "[LocationHandler][" + method + "]"

	code := ctx.Query(param)
	if code == "" {
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, param+" is required"))
		return
	}

	data, err := lookup(ctx.Request.Context(), code)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.%s; Error: %+v", logPrefix, method, err)
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, okMessage, logID, data))
}

func (h *Handler) Sync(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[LocationHandler][Sync]"
	reqCtx := ctx.Request.Context()

	var req dtolocation.SyncRequest
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	data, err := h.service.StartSync(reqCtx, req, authkit.ScopeFrom(reqCtx).ActorUserID())
	if err != nil {
		if errors.Is(err, domainlocation.ErrSyncRunning) {
			res := gokit.ErrorResponse(http.StatusConflict, msgSyncRunning, logID, msgSyncRunning)
			res.Data = data // the job that is already running
			ctx.JSON(http.StatusConflict, res)
			return
		}

		if errors.Is(err, domainlocation.ErrInvalidSync) {
			logus.LogContextf(ctx, logus.LevelDebug, "%s; Service.StartSync; Error: %+v", logPrefix, err)
			// The text of ErrInvalidSync errors is a fixed validation message
			// (NewInvalidSync), written for the caller.
			ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error()))
			return
		}

		logus.LogContextf(ctx, logus.LevelError, "%s; Service.StartSync; Error: %+v", logPrefix, err)
		res := gokit.InternalServerError(logID)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusAccepted, "Location sync started", logID, data)
	ctx.JSON(http.StatusAccepted, res)
}

func (h *Handler) GetSyncJob(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[LocationHandler][GetSyncJob]"
	reqCtx := ctx.Request.Context()

	jobID := ctx.Param("id")
	if jobID == "" {
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "sync job id is required"))
		return
	}

	data, err := h.service.GetSyncJob(reqCtx, jobID)
	if err != nil {
		if errors.Is(err, domainlocation.ErrNotFound) {
			ctx.JSON(http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, "location sync job not found"))
			return
		}

		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetSyncJob; Error: %+v", logPrefix, err)
		res := gokit.InternalServerError(logID)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get location sync job successfully", logID, data)
	ctx.JSON(http.StatusOK, res)
}
