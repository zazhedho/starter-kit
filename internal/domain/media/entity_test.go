package media

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMediaTableName(t *testing.T) {
	if got := (Media{}).TableName(); got != "media" {
		t.Fatalf("TableName = %q, want media", got)
	}
}

// Media is serialized as-is, so a json tag rename is an API change; pins the shape
// and that the soft-delete column is never serialized.
func TestMediaJSONShape(t *testing.T) {
	raw, err := json.Marshal(Media{ID: "m-1", CreatedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := []string{"id", "owner_user_id", "object_key", "url", "original_name", "content_type", "size", "created_at"}
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want exactly %v", got, want)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing json key %q", k)
		}
	}
}
