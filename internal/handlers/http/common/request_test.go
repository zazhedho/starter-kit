package handlercommon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestValidateUUIDKeepsHTTPValidationResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name      string
		value     string
		wantError string
	}{
		{name: "missing", wantError: "ID parameter is required"},
		{name: "invalid", value: "not-a-uuid", wantError: "ID must be a valid UUID"},
		{name: "valid", value: uuid.NewString()},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			if test.value != "" {
				ctx.Params = gin.Params{{Key: "id", Value: test.value}}
			}

			got, err := ValidateUUID(ctx, uuid.New())
			if test.wantError == "" {
				if err != nil || got != test.value {
					t.Fatalf("expected id %q, got %q, err=%v", test.value, got, err)
				}
				return
			}

			if err == nil || recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), test.wantError) {
				t.Fatalf("expected HTTP 400 with %q, status=%d body=%s err=%v", test.wantError, recorder.Code, recorder.Body.String(), err)
			}
		})
	}
}
