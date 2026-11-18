package servicelocation

import "testing"

// The expected strings are literals copied from the original cache package on
// purpose: they must not be derived from the code under test.
func TestCacheKeysAreByteIdentical(t *testing.T) {
	cases := []struct{ name, got, want string }{
		{"province", provinceKey(), "location:province"},
		{"city", cityKey("11"), "location:city:11"},
		{"district", districtKey("1101"), "location:district:1101"},
		{"village", villageKey("110101"), "location:village:110101"},
		{"prefix", cachePrefix, "location:"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s key = %q, want %q", c.name, c.got, c.want)
		}
	}
}
