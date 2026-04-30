package utils

import (
	"net/http/httptest"
	domainuser "starter-kit/internal/domain/user"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateJwtIncludesAccessClaims(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	token, err := GenerateJwt(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := JwtClaim(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}

	if claims["user_id"] != "user-1" || claims["token_type"] != "access" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestGenerateRefreshJwtIncludesRefreshTokenType(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	token, err := GenerateRefreshJwt(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1", nil)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := JwtClaim(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["token_type"] != "refresh" {
		t.Fatalf("expected refresh token type, got %+v", claims)
	}
}

func TestJwtClaimRejectsUnexpectedSigningMethod(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"user_id": "user-1"})
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign none token: %v", err)
	}

	if _, err := JwtClaim(tokenString); err == nil {
		t.Fatal("expected signing method error")
	}
}

func TestGetAuthTokenStripsBearerPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer abc.def.ghi")

	if got := GetAuthToken(ctx); got != "abc.def.ghi" {
		t.Fatalf("expected stripped bearer token, got %q", got)
	}
}
