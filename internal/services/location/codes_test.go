package location

import (
	"reflect"
	"testing"
)

func TestLocationHelperCacheKeysAndCodeNormalization(t *testing.T) {
	if got := normalizeChildCode("11", "01"); got != "1101" {
		t.Fatalf("expected normalized child code, got %q", got)
	}
	if got := normalizeChildCode("11", "1101"); got != "1101" {
		t.Fatalf("expected existing parent prefix to be preserved, got %q", got)
	}
	wantCandidates := []string{"01", "1101"}
	if got := childCodeCandidates("11", "1101"); !reflect.DeepEqual(got, wantCandidates) {
		t.Fatalf("expected %v, got %v", wantCandidates, got)
	}
}
