package serviceshared

import (
	domainmenu "starter-kit/internal/domain/menu"
	"testing"
)

func TestResolveAccessibleMenus_IncludesParentAndPreservesActiveOrder(t *testing.T) {
	parentID := "education"
	menus := []domainmenu.MenuItem{
		{Id: "dashboard", Name: "dashboard", DisplayName: "Dashboard", OrderIndex: 1, IsActive: true},
		{Id: "education-stats", Name: "education_stats", DisplayName: "Education Stats", ParentId: &parentID, OrderIndex: 10, IsActive: true},
		{Id: "education-priority", Name: "education_priority", DisplayName: "Education Priority", ParentId: &parentID, OrderIndex: 11, IsActive: true},
		{Id: "education", Name: "education", DisplayName: "Education", OrderIndex: 20, IsActive: true},
	}

	got := ResolveAccessibleMenus(menus, []string{"education_priority"})
	if len(got) != 2 {
		t.Fatalf("expected 2 menus, got %d", len(got))
	}
	if got[0].Id != "education-priority" {
		t.Fatalf("expected child menu first in active order, got %s", got[0].Id)
	}
	if got[1].Id != "education" {
		t.Fatalf("expected parent menu to be included, got %s", got[1].Id)
	}
}

func TestResolveAccessibleMenuIDs_IgnoresUnknownResources(t *testing.T) {
	menus := []domainmenu.MenuItem{
		{Id: "users", Name: "users", OrderIndex: 1, IsActive: true},
	}

	got := ResolveAccessibleMenuIDs(menus, []string{"unknown"})
	if len(got) != 0 {
		t.Fatalf("expected no menu ids, got %v", got)
	}
}
