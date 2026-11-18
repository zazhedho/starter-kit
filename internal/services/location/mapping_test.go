package location

import (
	"testing"

	domainlocation "starter-kit/internal/domain/location"
)

func TestLocationMapAndSortHelpers(t *testing.T) {
	provinces := sortProvinces([]domainlocation.Province{{Code: "12", Name: "Zulu"}, {Code: "11", Name: "Aceh"}})
	if provinces[0].Name != "Aceh" {
		t.Fatalf("expected province sort by name, got %+v", provinces)
	}
	cities := sortCities([]domainlocation.City{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if cities[0].Name != "Aceh" {
		t.Fatalf("expected city sort by name, got %+v", cities)
	}
	districts := sortDistricts([]domainlocation.District{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if districts[0].Name != "Aceh" {
		t.Fatalf("expected district sort by name, got %+v", districts)
	}
	villages := sortVillages([]domainlocation.Village{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if villages[0].Name != "Aceh" {
		t.Fatalf("expected village sort by name, got %+v", villages)
	}
	if got := mapCities([]domainlocation.City{{Code: "1101", Name: "Banda Aceh"}}); len(got) != 1 || got[0].Code != "1101" {
		t.Fatalf("unexpected city mapping: %+v", got)
	}
	if got := mapDistricts([]domainlocation.District{{Code: "110101", Name: "Kuta Alam"}}); len(got) != 1 || got[0].Name != "Kuta Alam" {
		t.Fatalf("unexpected district mapping: %+v", got)
	}
	if got := mapVillages([]domainlocation.Village{{Code: "11010101", Name: "Village"}}); len(got) != 1 || got[0].Code != "11010101" {
		t.Fatalf("unexpected village mapping: %+v", got)
	}
}
