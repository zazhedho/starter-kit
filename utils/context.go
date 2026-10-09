package utils

import (
	"context"

	"github.com/google/uuid"
)

type requestIDContextKey struct{}
type authDataContextKey struct{}

func WithRequestID(ctx context.Context, requestID uuid.UUID) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func WithAuthData(ctx context.Context, data map[string]any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, authDataContextKey{}, data)
}

func contextValue(ctx context.Context, key string) (any, bool) {
	if ctx == nil {
		return nil, false
	}

	switch key {
	case CtxKeyId:
		if value := ctx.Value(requestIDContextKey{}); value != nil {
			return value, true
		}
	case CtxKeyAuthData:
		if value := ctx.Value(authDataContextKey{}); value != nil {
			return value, true
		}
	}

	if getter, ok := ctx.(interface{ Get(string) (any, bool) }); ok {
		if value, exists := getter.Get(key); exists {
			return value, true
		}
	}
	value := ctx.Value(key)
	return value, value != nil
}

func setContextValue(ctx context.Context, key string, value any) {
	if setter, ok := ctx.(interface{ Set(string, any) }); ok {
		setter.Set(key, value)
	}
}
