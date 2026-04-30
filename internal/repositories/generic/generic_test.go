package repositorygeneric

import "testing"

func TestContains(t *testing.T) {
	if !contains([]string{"name", "created_at"}, "name") {
		t.Fatal("expected value to be found")
	}
	if contains([]string{"name"}, "email") {
		t.Fatal("expected value to be missing")
	}
}

func TestIsSliceValue(t *testing.T) {
	if !isSliceValue([]string{"a", "b"}) {
		t.Fatal("expected string slice to be detected")
	}
	if isSliceValue([]byte("abc")) {
		t.Fatal("expected byte slice to be ignored")
	}
	if isSliceValue("abc") {
		t.Fatal("expected scalar to be ignored")
	}
}

func TestZeroValue(t *testing.T) {
	if got := zeroValue[string](); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
	type sample struct{ Name string }
	if got := zeroValue[sample](); got.Name != "" {
		t.Fatalf("expected zero struct, got %+v", got)
	}
}
