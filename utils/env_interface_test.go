package utils

import (
	"reflect"
	"testing"
	"time"
)

func TestGetEnvParsesCommonTypes(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	t.Setenv("TEST_BOOL", "true")
	t.Setenv("TEST_DURATION", "90s")
	t.Setenv("TEST_FLOAT", "3.5")

	if got := GetEnv("TEST_INT", 0); got != 42 {
		t.Fatalf("expected int 42, got %d", got)
	}
	if got := GetEnv("TEST_BOOL", false); !got {
		t.Fatalf("expected bool true")
	}
	if got := GetEnv("TEST_DURATION", time.Second); got != 90*time.Second {
		t.Fatalf("expected 90s, got %v", got)
	}
	if got := GetEnv("TEST_FLOAT", 0.0); got != 3.5 {
		t.Fatalf("expected 3.5, got %v", got)
	}
}

func TestGetEnvFallsBackForInvalidValue(t *testing.T) {
	t.Setenv("TEST_INT_INVALID", "not-int")
	if got := GetEnv("TEST_INT_INVALID", 7); got != 7 {
		t.Fatalf("expected fallback value, got %d", got)
	}
}

func TestConvertValuesToStringConvertsSelectedKeys(t *testing.T) {
	got := ConvertValuesToString(map[string]interface{}{
		"id":     123,
		"active": true,
		"ids":    []interface{}{"1", "2"},
	}, "id", "ids")

	want := map[string]interface{}{
		"id":     "123",
		"active": true,
		"ids":    `["1","2"]`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
}

func TestNormalizeUUIDPointer(t *testing.T) {
	if got := NormalizeUUIDPointer(""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", *got)
	}
	if got := NormalizeUUIDPointer("not-a-uuid"); got != nil {
		t.Fatalf("expected nil for invalid uuid, got %v", *got)
	}

	id := "550e8400-e29b-41d4-a716-446655440000"
	got := NormalizeUUIDPointer(" " + id + " ")
	if got == nil || *got != id {
		t.Fatalf("expected normalized uuid pointer, got %v", got)
	}
}

func TestNormalizePhoneAndEmail(t *testing.T) {
	if got := NormalizePhoneTo62("+62 812-3456-789"); got != "628123456789" {
		t.Fatalf("unexpected phone normalization: %q", got)
	}
	if got := NormalizePhoneTo62("0812 3456 789"); got != "628123456789" {
		t.Fatalf("unexpected phone normalization: %q", got)
	}
	if got := SanitizeEmail(" Jane.Doe@Example.COM "); got != "jane.doe@example.com" {
		t.Fatalf("unexpected email sanitization: %q", got)
	}
}
