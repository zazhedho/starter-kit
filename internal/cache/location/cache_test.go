package locationcache

import (
	"context"
	"testing"
	"time"

	"starter-kit/internal/dto"

	redismock "github.com/go-redis/redismock/v9"
)

func TestKeys(t *testing.T) {
	if ProvinceKey() != "location:province" {
		t.Fatalf("unexpected province cache key")
	}
	if CityKey("11") != "location:city:11" || DistrictKey("1101") != "location:district:1101" || VillageKey("110101") != "location:village:110101" {
		t.Fatal("unexpected scoped cache keys")
	}
	if Prefix() != "location:" {
		t.Fatal("unexpected cache prefix")
	}
}

func TestGetSetDeleteUseRedis(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectGet("location:province").SetVal(`[{"code":"11","name":"Aceh"}]`)
	got, ok := Get(ctx, client, "location:province")
	if !ok || len(got) != 1 || got[0].Code != "11" {
		t.Fatalf("expected cached locations, ok=%v got=%+v", ok, got)
	}

	ttl := 3 * time.Hour
	mock.Regexp().ExpectSet("location:province", `.+`, ttl).SetVal("OK")
	Set(ctx, client, "location:province", []dto.Location{{Code: "11", Name: "Aceh"}}, ttl)

	mock.ExpectScan(0, "location:*", 100).SetVal([]string{"location:province", "location:city:11"}, 0)
	mock.ExpectDel("location:province", "location:city:11").SetVal(2)
	DeleteKeys(ctx, client, "location:")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestNilClientMissAndNoop(t *testing.T) {
	ctx := context.Background()

	if got, ok := Get(ctx, nil, "location:province"); ok {
		t.Fatalf("expected cache miss, got %+v", got)
	}

	Set(ctx, nil, "location:province", []dto.Location{{Code: "11", Name: "Aceh"}}, time.Hour)
	DeleteKeys(ctx, nil, "location:")
}
