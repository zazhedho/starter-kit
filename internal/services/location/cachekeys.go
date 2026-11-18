package location

import "fmt"

// Cache key formats. Deployed Redis data uses these exact strings, so they
// must never change without a migration plan; cachekeys_test.go pins them.
const cachePrefix = "location:"

func provinceKey() string { return "location:province" }

func cityKey(provinceCode string) string { return fmt.Sprintf("location:city:%s", provinceCode) }

func districtKey(cityCode string) string { return fmt.Sprintf("location:district:%s", cityCode) }

func villageKey(districtCode string) string { return fmt.Sprintf("location:village:%s", districtCode) }
