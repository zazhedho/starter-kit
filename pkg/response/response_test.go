package response

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestResponseSetsStatusFromCode(t *testing.T) {
	logID := uuid.New()

	success := Response(http.StatusCreated, "created", logID, map[string]string{"id": "1"})
	if !success.Status || success.Id != logID || success.Message != "created" {
		t.Fatalf("unexpected success response: %+v", success)
	}

	failed := Response(http.StatusBadRequest, "bad request", logID, nil)
	if failed.Status {
		t.Fatalf("expected failed status for 400, got %+v", failed)
	}
}

func TestErrorHelpersHideInternalDetails(t *testing.T) {
	logID := uuid.New()

	got := InternalServerError(logID)
	if got.Status {
		t.Fatalf("expected error status, got %+v", got)
	}

	errBody, ok := got.Error.(Errors)
	if !ok {
		t.Fatalf("expected response.Errors, got %#v", got.Error)
	}
	if errBody.Code != http.StatusInternalServerError || errBody.Message != "Internal server error" {
		t.Fatalf("unexpected error body: %+v", errBody)
	}
}

func TestPaginationResponseCalculatesPageState(t *testing.T) {
	got := PaginationResponse(http.StatusOK, 55, 2, 20, uuid.New(), []string{"item"})

	if got.TotalPages != 3 {
		t.Fatalf("expected 3 total pages, got %d", got.TotalPages)
	}
	if !got.NextPage || !got.PrevPage {
		t.Fatalf("expected next and previous page flags, got %+v", got)
	}
	if got.Limit != 20 || got.TotalData != 55 {
		t.Fatalf("unexpected pagination metadata: %+v", got)
	}
}
