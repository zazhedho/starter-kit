package utils

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func CreateUUID() string {
	var id string
	if uuid7, err := uuid.NewV7(); err == nil {
		id = uuid7.String()
	} else {
		id = uuid.NewString()
	}

	return id
}

func GenerateLogId(ctx *gin.Context) uuid.UUID {
	if logId, ok := ctx.Value(CtxKeyId).(uuid.UUID); ok {
		return logId
	}

	logId, err := uuid.NewV7()
	if err != nil {
		logId = uuid.New()
	}

	return logId
}
