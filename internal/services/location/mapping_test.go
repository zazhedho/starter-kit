package location

import (
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
)

func TestViewsMapEveryLevelToLocations(t *testing.T) {
	if got := views([]domainlocation.Province{{Code: "11", Name: "Aceh"}}, viewProvince); len(got) != 1 || got[0].Code != "11" || got[0].Name != "Aceh" {
		t.Fatalf("province view: %+v", got)
	}
	if got := views([]domainlocation.City{{Code: "1101", Name: "Banda Aceh"}}, viewCity); len(got) != 1 || got[0].Code != "1101" {
		t.Fatalf("city view: %+v", got)
	}
	if got := views([]domainlocation.District{{Code: "110101", Name: "Kuta Alam"}}, viewDistrict); len(got) != 1 || got[0].Name != "Kuta Alam" {
		t.Fatalf("district view: %+v", got)
	}
	if got := views([]domainlocation.Village{{Code: "11010101", Name: "Village"}}, viewVillage); len(got) != 1 || got[0].Code != "11010101" {
		t.Fatalf("village view: %+v", got)
	}
	if got := views[domainlocation.City](nil, viewCity); got == nil || len(got) != 0 {
		t.Fatalf("no rows must map to an empty, non-nil list (it is sent as []), got %#v", got)
	}
}

func TestMapSyncJobFormatsTimesAndOmitsInternalFields(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := mapSyncJob(domainlocation.SyncJob{
		ID: "job-1", Status: "running", RequestedBy: "user-1", CreatedAt: created, StartedAt: &created,
		OwnerInstanceID: "instance-a", HeartbeatAt: created,
	})
	if got.CreatedAt != "2026-01-02T03:04:05Z" || got.StartedAt != "2026-01-02T03:04:05Z" || got.FinishedAt != "" || got.RequestedBy != "user-1" {
		t.Fatalf("mapSyncJob = %+v", got)
	}
}
