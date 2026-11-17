package database

import (
	"reflect"
	"testing"
)

func TestSessionTimeZoneParams(t *testing.T) {
	cases := []struct {
		name      string
		in        map[string]string
		zoneInURL bool
		want      map[string]string
	}{
		{"none present", map[string]string{"application_name": "x"}, false,
			map[string]string{"application_name": "x", "TimeZone": "Asia/Jakarta"}},
		{"PGTZ-style lowercase replaced", map[string]string{"timezone": "UTC"}, false,
			map[string]string{"TimeZone": "Asia/Jakarta"}},
		{"mixed case replaced", map[string]string{"TIMEZONE": "UTC", "TimeZone": "UTC"}, false,
			map[string]string{"TimeZone": "Asia/Jakarta"}},
		{"no zone written in the URL, PGTZ merged in by pgx", map[string]string{"timezone": "UTC"}, false,
			map[string]string{"TimeZone": "Asia/Jakarta"}},
		{"url, none present", map[string]string{}, false,
			map[string]string{"TimeZone": "Asia/Jakarta"}},
		{"url, own timezone kept", map[string]string{"timezone": "UTC"}, true,
			map[string]string{"timezone": "UTC"}},
		{"url, own TimeZone kept", map[string]string{"TimeZone": "UTC"}, true,
			map[string]string{"TimeZone": "UTC"}},
		{"nil input", nil, false, map[string]string{"TimeZone": "Asia/Jakarta"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sessionParams(c.in, "Asia/Jakarta", c.zoneInURL); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("sessionParams = %v, want %v", got, c.want)
			}
		})
	}
}

func TestURLNamesTimeZone(t *testing.T) {
	cases := map[string]bool{
		"":                         false,
		"postgres://u:p@h:5432/db": false,
		"postgres://u:p@h:5432/db?sslmode=disable":         false,
		"postgres://u:p@h/db?timezone=UTC":                 true,
		"postgresql://u:p@h/db?TimeZone=UTC":               true,
		"postgres://u:p@h/db?sslmode=disable&TIMEZONE=UTC": true,
		"host=h user=u timezone=UTC":                       true,
		"host=h user=u TimeZone='UTC'":                     true,
		"host=h user=u":                                    false,
	}
	for raw, want := range cases {
		if got := urlNamesTimeZone(raw); got != want {
			t.Errorf("urlNamesTimeZone(%q) = %v, want %v", raw, got, want)
		}
	}
}
