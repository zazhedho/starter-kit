package location

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
	httpshared "starter-kit/internal/handlers/http/shared"
)

const msgSyncRunning = "Location sync is already running"

type Handler struct {
	service Service
}

func New(s Service) *Handler {
	return &Handler{service: s}
}

func (h *Handler) GetProvince(ctx *gin.Context) {
	data, err := h.service.GetProvince(ctx.Request.Context())
	if err != nil {
		fail(ctx, "GetProvince", err)
		return
	}
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, "Get province successfully", gokit.RequestID(ctx), data))
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

func (h *Handler) listByParent(ctx *gin.Context, method, param, okMessage string, lookup func(context.Context, string) ([]dtolocation.Location, error)) {
	code := ctx.Query(param)
	if code == "" {
		httpshared.Write(ctx, http.StatusBadRequest, param+" is required")
		return
	}

	data, err := lookup(ctx.Request.Context(), code)
	if err != nil {
		fail(ctx, method, err)
		return
	}
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, okMessage, gokit.RequestID(ctx), data))
}

func (h *Handler) Sync(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	reqCtx := ctx.Request.Context()

	var req dtolocation.SyncRequest
	if !gokit.BindJSON(ctx, logID, "[LocationHandler][Sync]", &req) {
		return
	}

	data, err := h.service.StartSync(reqCtx, req, authkit.ScopeFrom(reqCtx).ActorUserID())
	if errors.Is(err, domainlocation.ErrSyncRunning) {
		httpshared.Log(ctx, http.StatusConflict, "[LocationHandler][Sync]", "Service.StartSync", err)
		res := gokit.ErrorResponse(http.StatusConflict, msgSyncRunning, logID, msgSyncRunning)
		res.Data = data
		ctx.JSON(http.StatusConflict, res)
		return
	}
	if err != nil {
		fail(ctx, "Sync", err)
		return
	}

	ctx.JSON(http.StatusAccepted, gokit.Response(http.StatusAccepted, "Location sync started", logID, data))
}

func (h *Handler) GetSyncJob(ctx *gin.Context) {
	id, err := gokit.ValidateUUIDParam(ctx, gokit.RequestID(ctx))
	if err != nil {
		return
	}

	data, err := h.service.GetSyncJob(ctx.Request.Context(), id)
	if err != nil {
		fail(ctx, "GetSyncJob", err)
		return
	}
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, "Get location sync job successfully", gokit.RequestID(ctx), data))
}

func fail(ctx *gin.Context, method string, err error) {
	status, detail := locationErrorResponse(err)
	httpshared.Log(ctx, status, "[LocationHandler]["+method+"]", "Service."+method, err)
	httpshared.Write(ctx, status, detail)
}

func locationErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, domainlocation.ErrInvalidCode), errors.Is(err, domainlocation.ErrInvalidSync):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, domainlocation.ErrSyncJobNotFound):
		return http.StatusNotFound, "location sync job not found"
	case errors.Is(err, domainlocation.ErrNotFound):
		return http.StatusNotFound, "location not found"
	case errors.Is(err, domainlocation.ErrSyncRunning):
		return http.StatusConflict, msgSyncRunning
	case errors.Is(err, domainlocation.ErrUpstream):
		return http.StatusBadGateway, "the location service is not available"
	case errors.Is(err, domainlocation.ErrShuttingDown):
		return http.StatusServiceUnavailable, "the service is shutting down"
	default:
		return http.StatusInternalServerError, gokit.MsgSomethingWrong
	}
}
