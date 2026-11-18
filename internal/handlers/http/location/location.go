package handlerlocation

import (
	"errors"
	"fmt"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	"net/http"
	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"

	"github.com/gin-gonic/gin"
)

type LocationHandler struct {
	service Service
}

func NewLocationHandler(s Service) *LocationHandler {
	return &LocationHandler{service: s}
}

func (h *LocationHandler) GetProvince(ctx *gin.Context) {
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

func (h *LocationHandler) GetCity(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetCity]"
	reqCtx := ctx.Request.Context()

	provinceCode := ctx.Query("province_code")
	if provinceCode == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "province_code is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, err := h.service.GetCity(reqCtx, provinceCode)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetCity; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get city successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) GetDistrict(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetDistrict]"
	reqCtx := ctx.Request.Context()

	cityCode := ctx.Query("city_code")
	if cityCode == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "city_code is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, err := h.service.GetDistrict(reqCtx, cityCode)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetDistrict; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get district successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) GetVillage(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetVillage]"
	reqCtx := ctx.Request.Context()

	districtCode := ctx.Query("district_code")
	if districtCode == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "district_code is required"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	data, err := h.service.GetVillage(reqCtx, districtCode)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetVillage; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "Get village successfully", logId, data)
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) Sync(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][Sync]"
	reqCtx := ctx.Request.Context()

	var req dto.SyncLocationRequest
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	data, err := h.service.StartSync(reqCtx, req)
	if err != nil {
		if errors.Is(err, domainlocation.ErrSyncRunning) {
			res := gokit.Response(http.StatusConflict, gokit.MsgSomethingWrong, logId, data)
			res.Error = gokit.Errors{Code: http.StatusConflict, Message: err.Error()}
			ctx.JSON(http.StatusConflict, res)
			return
		}

		if errors.Is(err, domainlocation.ErrInvalidSync) {
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

func (h *LocationHandler) GetSyncJob(ctx *gin.Context) {
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
