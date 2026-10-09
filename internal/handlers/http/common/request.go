package handlercommon

import (
	"errors"
	"net/http"

	"starter-kit/pkg/response"
	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ValidateUUID(ctx *gin.Context, logID uuid.UUID) (string, error) {
	id, err := utils.ValidateUUID(ctx.Param("id"))
	if err == nil {
		return id, nil
	}

	res := response.Response(http.StatusBadRequest, http.StatusText(http.StatusBadRequest), logID, nil)
	if errors.Is(err, utils.ErrMissingID) {
		res.Error = "ID parameter is required"
	} else {
		res.Error = response.Errors{Code: http.StatusBadRequest, Message: "ID must be a valid UUID"}
	}
	ctx.JSON(http.StatusBadRequest, res)
	return "", err
}
