package handlerlocation

import (
	"fmt"
	"net/http"
	interfacelocation "starter-kit/internal/interfaces/location"
	"starter-kit/pkg/logger"
	"starter-kit/pkg/messages"
	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
)

type LocationHandler struct {
	Service interfacelocation.ServiceLocationInterface
}

func NewLocationHandler(s interfacelocation.ServiceLocationInterface) *LocationHandler {
	return &LocationHandler{
		Service: s,
	}
}

func (h *LocationHandler) GetProvince(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetProvince]"

	year := ctx.DefaultQuery("thn", utils.GetEnv("PROVINCE_YEAR", "2025").(string))
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Query Year: %s;", logPrefix, year))

	data, err := h.Service.GetProvince(year)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetProvince; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get province successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) GetCity(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetCity]"

	year := ctx.DefaultQuery("thn", utils.GetEnv("PROVINCE_YEAR", "2025").(string))
	lvl := ctx.DefaultQuery("lvl", "11")
	pro := ctx.Query("pro")

	if pro == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: pro", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'pro' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Query params - year: %s, lvl: %s, pro: %s;", logPrefix, year, lvl, pro))

	data, err := h.Service.GetCity(year, lvl, pro)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetCity; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get city successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) GetDistrict(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetDistrict]"

	year := ctx.DefaultQuery("thn", utils.GetEnv("PROVINCE_YEAR", "2025").(string))
	lvl := ctx.DefaultQuery("lvl", "12")
	pro := ctx.Query("pro")
	kab := ctx.Query("kab")

	if pro == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: pro", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'pro' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if kab == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: kab", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'kab' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Query params - year: %s, lvl: %s, pro: %s, kab: %s;", logPrefix, year, lvl, pro, kab))

	data, err := h.Service.GetDistrict(year, lvl, pro, kab)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetDistrict; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get district successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *LocationHandler) GetVillage(ctx *gin.Context) {
	logId := utils.GenerateLogId(ctx)
	logPrefix := "[LocationHandler][GetVillage]"

	year := ctx.DefaultQuery("thn", utils.GetEnv("PROVINCE_YEAR", "2025").(string))
	lvl := ctx.DefaultQuery("lvl", "13")
	pro := ctx.Query("pro")
	kab := ctx.Query("kab")
	kec := ctx.Query("kec")

	if pro == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: pro", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'pro' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if kab == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: kab", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'kab' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if kec == "" {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Missing required parameter: kec", logPrefix))
		res := response.Response(http.StatusBadRequest, "Parameter 'kec' is required", logId, nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Query params - year: %s, lvl: %s, pro: %s, kab: %s, kec: %s;", logPrefix, year, lvl, pro, kab, kec))

	data, err := h.Service.GetVillage(year, lvl, pro, kab, kec)
	if err != nil {
		logger.WriteLogWithContext(ctx, logger.LogLevelError, fmt.Sprintf("%s; Service.GetVillage; Error: %+v", logPrefix, err))
		res := response.Response(http.StatusInternalServerError, messages.MsgFail, logId, nil)
		res.Error = err.Error()
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := response.Response(http.StatusOK, "Get village successfully", logId, data)
	logger.WriteLogWithContext(ctx, logger.LogLevelDebug, fmt.Sprintf("%s; Success: %+v;", logPrefix, utils.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}
