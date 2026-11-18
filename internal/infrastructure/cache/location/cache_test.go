package location

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redismock "github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"

	dtolocation "starter-kit/internal/dto/location"
)

func TestGetSetDeleteUseRedis(t *testing.T) {
	client, mock := redismock.NewClientMock()
	ctx := context.Background()

	mock.ExpectGet("location:province").SetVal(`[{"code":"11","name":"Aceh"}]`)
	got, ok := New(client).Get(ctx, "location:province")
	if !ok || len(got) != 1 || got[0].Code != "11" {
		t.Fatalf("expected cached locations, ok=%v got=%+v", ok, got)
	}

	ttl := 3 * time.Hour
	mock.Regexp().ExpectSet("location:province", `.+`, ttl).SetVal("OK")
	New(client).Set(ctx, "location:province", []dtolocation.Location{{Code: "11", Name: "Aceh"}}, ttl)

	mock.ExpectScan(0, "location:*", 100).SetVal([]string{"location:province", "location:city:11"}, 0)
	mock.ExpectDel("location:province", "location:city:11").SetVal(2)
	New(client).DeleteKeys(ctx, "location:")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestNilClientMissAndNoop(t *testing.T) {
	ctx := context.Background()

	if got, ok := New(nil).Get(ctx, "location:province"); ok {
		t.Fatalf("expected cache miss, got %+v", got)
	}

	New(nil).Set(ctx, "location:province", []dtolocation.Location{{Code: "11", Name: "Aceh"}}, time.Hour)
	New(nil).DeleteKeys(ctx, "location:")
}

func TestRedisKeysStoredAsGiven(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := New(client)
	ctx := context.Background()

	for _, key := range []string{"location:province", "location:city:11", "location:district:1101", "location:village:110101"} {
		cache.Set(ctx, key, []dtolocation.Location{{Code: "11", Name: "Aceh"}}, time.Hour)
		if !mr.Exists(key) {
			t.Fatalf("key %q was not stored verbatim", key)
		}
	}
	cache.DeleteKeys(ctx, "location:")
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected the prefix delete to clear everything, left %v", keys)
	}
}
