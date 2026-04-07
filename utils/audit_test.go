package utils

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetImpersonationMetadataReturnsNilForRegularSession(t *testing.T) {
	ctx := &gin.Context{}
	ctx.Set(CtxKeyAuthData, map[string]interface{}{
		"user_id": "user-1",
		"role":    "staff",
	})

	got := GetImpersonationMetadata(ctx)
	if got != nil {
		t.Fatalf("expected nil metadata for regular session, got %v", got)
	}
}

func TestGetImpersonationMetadataReturnsOriginalActorData(t *testing.T) {
	ctx := &gin.Context{}
	ctx.Set(CtxKeyAuthData, map[string]interface{}{
		"user_id":           "target-1",
		"username":          "Target User",
		"role":              "viewer",
		"is_impersonated":   true,
		"original_user_id":  "admin-1",
		"original_username": "Admin User",
		"original_role":     "admin",
	})

	got := GetImpersonationMetadata(ctx)
	if got == nil {
		t.Fatal("expected impersonation metadata")
	}

	if got["is_impersonated"] != true {
		t.Fatalf("expected impersonation flag, got %v", got["is_impersonated"])
	}
	if got["original_user_id"] != "admin-1" {
		t.Fatalf("expected original user id, got %v", got["original_user_id"])
	}
	if got["original_role"] != "admin" {
		t.Fatalf("expected original role, got %v", got["original_role"])
	}
	if got["impersonated_user_id"] != "target-1" {
		t.Fatalf("expected impersonated user id, got %v", got["impersonated_user_id"])
	}
	if got["impersonated_role"] != "viewer" {
		t.Fatalf("expected impersonated role, got %v", got["impersonated_role"])
	}
}

func TestGetActorContextUsesOriginalActorForImpersonatedSession(t *testing.T) {
	ctx := &gin.Context{}
	ctx.Set(CtxKeyAuthData, map[string]interface{}{
		"user_id":           "target-1",
		"role":              "viewer",
		"is_impersonated":   true,
		"original_user_id":  "admin-1",
		"original_username": "Admin User",
		"original_role":     "admin",
	})

	userID, role := GetActorContext(ctx)
	if userID != "admin-1" {
		t.Fatalf("expected original actor user id, got %q", userID)
	}
	if role != "admin" {
		t.Fatalf("expected original actor role, got %q", role)
	}
}

func TestMergeMetadataPreservesBaseAndExtra(t *testing.T) {
	base := map[string]interface{}{"a": 1}
	extra := map[string]interface{}{"b": 2}

	got := MergeMetadata(base, extra)
	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %v", got)
	}
	if got["a"] != 1 || got["b"] != 2 {
		t.Fatalf("unexpected merged metadata: %v", got)
	}
}
