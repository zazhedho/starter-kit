package authscope

import (
	"context"
	"testing"
)

func TestNewFromClaimsNormalizesPermissionsAndImpersonation(t *testing.T) {
	scope := NewFromClaims(map[string]interface{}{
		"user_id":           " user-1 ",
		"username":          " Jane ",
		"role":              "admin",
		"is_impersonated":   true,
		"original_user_id":  "admin-1",
		"original_username": "Admin",
		"original_role":     "superadmin",
	}, []string{" Users:List ", "invalid", "roles:update"})

	if scope.UserID != "user-1" {
		t.Fatalf("expected trimmed user id, got %q", scope.UserID)
	}
	if !scope.Has("users", "list") {
		t.Fatal("expected users:list permission")
	}
	if !scope.Has("ROLES", "UPDATE") {
		t.Fatal("expected case-insensitive roles:update permission")
	}
	if scope.Has("invalid", "") {
		t.Fatal("expected invalid permission key to be ignored")
	}
	if !scope.IsImpersonated || scope.OriginalUserID != "admin-1" {
		t.Fatalf("expected impersonation claims, got %+v", scope)
	}
}

func TestFromContextReturnsEmptyScopeWhenMissing(t *testing.T) {
	scope := FromContext(context.Background())
	if scope.UserID != "" {
		t.Fatalf("expected empty user id, got %q", scope.UserID)
	}
	if scope.Permissions == nil {
		t.Fatal("expected non-nil permissions map")
	}
}

func TestSuperadminHasEveryPermission(t *testing.T) {
	scope := New("user-1", "Root", "superadmin", nil)
	if !scope.Has("anything", "delete") {
		t.Fatal("expected superadmin to bypass permission map")
	}
}
