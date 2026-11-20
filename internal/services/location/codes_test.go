package location

import (
	"strings"
	"testing"
)

func TestIsCode(t *testing.T) {
	valid := []string{"1", "11", "3171", "0", "007", strings.Repeat("9", 20)}
	invalid := []string{"", " ", "3*", "31?", "[1-9]", "31.71", "3 1", "31\n", "３１", "-1", "a", "1e5", strings.Repeat("9", 21)}
	for _, c := range valid {
		if !isCode(c) {
			t.Errorf("isCode(%q) = false, want true", c)
		}
	}
	for _, c := range invalid {
		if isCode(c) {
			t.Errorf("isCode(%q) = true, want false", c)
		}
	}
}

func TestChildCode(t *testing.T) {
	cases := []struct {
		name, parent, raw, want string
		ok                      bool
	}{
		{"a province needs no parent", "", "31", "31", true},
		{"relative code gets the parent prefix", "11", "01", "1101", true},
		{"full code is kept", "11", "1101", "1101", true},
		{"village under a district", "167101", "1001", "1671011001", true},
		{"same length as the parent is relative", "31", "31", "3131", true},
		{"a longer code of another parent is refused", "31", "1101", "", false},
		{"a longer foreign district code is refused", "3171", "110101", "", false},
		{"a non-digit code is refused", "31", "7a", "", false},
		{"an empty code is refused", "31", "", "", false},
		{"a glob is refused", "31", "*", "", false},
		{"a province too long is refused", "", strings.Repeat("1", 21), "", false},
		{"a combined code too long is refused", strings.Repeat("1", 15), strings.Repeat("2", 6), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := childCode(c.parent, c.raw)
			if got != c.want || ok != c.ok {
				t.Fatalf("childCode(%q, %q) = (%q, %v), want (%q, %v)", c.parent, c.raw, got, ok, c.want, c.ok)
			}
		})
	}
}

func TestChildCodeParam(t *testing.T) {
	cases := []struct{ parent, code, want string }{
		{"31", "3171", "71"},
		{"31", "71", "71"},
		{"3171", "317101", "01"},
		{"", "31", "31"},
		{"31", "31", "31"},
	}
	for _, c := range cases {
		if got := childCodeParam(c.parent, c.code); got != c.want {
			t.Errorf("childCodeParam(%q, %q) = %q, want %q", c.parent, c.code, got, c.want)
		}
	}
}
