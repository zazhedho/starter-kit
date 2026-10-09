package utils

import "context"

func GetAuthData(ctx context.Context) map[string]any {
	jwtClaims, _ := contextValue(ctx, CtxKeyAuthData)
	if data, ok := jwtClaims.(map[string]any); ok {
		return data
	}
	return nil
}
