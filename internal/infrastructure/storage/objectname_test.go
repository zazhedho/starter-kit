package storage

import (
	"strings"
	"testing"
)

func TestBuildObjectNameKeepsExtensionAndTrimsFolder(t *testing.T) {
	got := buildObjectName("avatar.png", "/users/")
	if !strings.HasPrefix(got, "users/") {
		t.Fatalf("expected folder prefix, got %q", got)
	}
	if !strings.HasSuffix(got, ".png") {
		t.Fatalf("expected extension to be preserved, got %q", got)
	}

	got = buildObjectName("report", "")
	if strings.Contains(got, "/") || strings.HasSuffix(got, ".") {
		t.Fatalf("expected bare generated object name without folder or extension, got %q", got)
	}
}
