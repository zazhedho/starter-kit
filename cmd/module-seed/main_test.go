package main

import (
	"reflect"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	tests := map[string][]string{
		"":                         nil,
		"admin, superadmin,,staff": {"admin", "superadmin", "staff"},
		" list , view ":            {"list", "view"},
	}

	for input, want := range tests {
		if got := splitCSV(input); !reflect.DeepEqual(got, want) {
			t.Fatalf("input %q: expected %v, got %v", input, want, got)
		}
	}
}
