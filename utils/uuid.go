package utils

import (
	"context"
	"strings"

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

func GenerateLogId(ctx context.Context) uuid.UUID {
	if ctx != nil {
		if storedID, ok := contextValue(ctx, CtxKeyId); ok {
			switch v := storedID.(type) {
			case uuid.UUID:
				return v
			case string:
				if parsedID, err := uuid.Parse(v); err == nil {
					return parsedID
				}
			}
		}
	}

	logId, err := uuid.NewV7()
	if err != nil {
		logId = uuid.New()
	}

	if ctx != nil {
		setContextValue(ctx, CtxKeyId, logId)
	}

	return logId
}

func NormalizeUUIDPointer(input string) *string {
	value := strings.TrimSpace(input)
	if value == "" {
		return nil
	}

	if _, err := uuid.Parse(value); err != nil {
		return nil
	}

	return &value
}
