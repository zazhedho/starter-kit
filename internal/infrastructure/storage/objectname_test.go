package storage

import (
	"regexp"
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

func TestBuildObjectNameCarriesAFullRandomUUID(t *testing.T) {
	pattern := regexp.MustCompile(`^media/\d{8}_\d{6}_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.png$`)
	seen := map[string]bool{}
	for range 50 {
		got := buildObjectName("upload.png", "media")
		if !pattern.MatchString(got) {
			t.Fatalf("object name %q does not carry a v4 UUID", got)
		}
		id := got[strings.LastIndex(got, "_")+1:]
		if seen[id] {
			t.Fatalf("duplicate id in %q", got)
		}
		seen[id] = true
	}
}
