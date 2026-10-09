package middlewares

import (
	"net/http/httptest"
	"testing"

	"starter-kit/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestSetContextIDPropagatesRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, header := range []string{"", uuid.NewString()} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest("GET", "/", nil)
		if header != "" {
			ctx.Request.Header.Set("X-Request-ID", header)
		}

		SetContextId()(ctx)

		requestID, err := uuid.Parse(ctx.Writer.Header().Get("X-Request-ID"))
		if err != nil {
			t.Fatalf("expected response request id, got %v", err)
		}
		if got := utils.GenerateLogId(ctx.Request.Context()); got != requestID {
			t.Fatalf("expected request context id %s, got %s", requestID, got)
		}
	}
}
