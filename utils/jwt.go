package utils

import (
	"errors"
	"fmt"
	"os"
	domainuser "starter-kit/internal/domain/user"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AppClaims struct {
	UserId           string `json:"user_id"`
	Username         string `json:"username"`
	Role             string `json:"role"`
	TokenType        string `json:"token_type,omitempty"`
	IsImpersonated   bool   `json:"is_impersonated,omitempty"`
	OriginalUserId   string `json:"original_user_id,omitempty"`
	OriginalUsername string `json:"original_username,omitempty"`
	OriginalRole     string `json:"original_role,omitempty"`
	*jwt.RegisteredClaims
}

func GenerateJwt(user *domainuser.Users, logId string) (string, error) {
	return GenerateJwtWithClaims(user, logId, nil)
}

func GenerateJwtWithClaims(user *domainuser.Users, logId string, claimsOverride *AppClaims) (string, error) {
	accessExp := time.Now().Add(time.Hour * time.Duration(GetEnv("JWT_EXP", 24)))
	claims := AppClaims{
		UserId:    user.Id,
		Username:  user.Name,
		Role:      user.Role,
		TokenType: "access",
		RegisteredClaims: &jwt.RegisteredClaims{
			ID:        logId,
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		if claimsOverride.TokenType != "" {
			claims.TokenType = claimsOverride.TokenType
		}
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.OriginalUserId = claimsOverride.OriginalUserId
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)

	signedToken, err := token.SignedString([]byte(os.Getenv("JWT_KEY")))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func GenerateRefreshJwt(user *domainuser.Users, logId string, claimsOverride *AppClaims) (string, error) {
	refreshExp := time.Now().Add(time.Hour * time.Duration(GetEnv("REFRESH_TOKEN_EXP_HOURS", 168)))
	claims := &AppClaims{
		UserId:    user.Id,
		Username:  user.Name,
		Role:      user.Role,
		TokenType: "refresh",
		RegisteredClaims: &jwt.RegisteredClaims{
			ID:        logId,
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.OriginalUserId = claimsOverride.OriginalUserId
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_KEY")))
}

func GetAuthToken(ctx *gin.Context) string {
	bearerToken := ctx.Request.Header.Get("Authorization")
	return strings.ReplaceAll(bearerToken, "Bearer ", "")
}

func JwtClaims(ctx *gin.Context) (string, map[string]interface{}, error) {
	tokenString := GetAuthToken(ctx)
	data, err := JwtClaim(tokenString)
	return tokenString, data, err
}

func JwtClaim(tokenString string) (map[string]interface{}, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		hmacSecretString := GetEnv("JWT_KEY", "")
		hmacSecret := []byte(hmacSecretString)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return hmacSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}
