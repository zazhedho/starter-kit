package architecture

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var migrationName = regexp.MustCompile(`^(\d{14})_[a-z0-9]+_[a-z0-9_]+\.(up|down)\.sql$`)

func migrationProblems(names []string) []string {
	var problems []string
	direction := map[string]map[string]bool{}
	versionOwner := map[string]string{}
	for _, n := range names {
		m := migrationName.FindStringSubmatch(n)
		if m == nil {
			problems = append(problems, n+": name must match <14-digit UTC timestamp>_<module>_<change>.(up|down).sql")
			continue
		}
		stem := strings.TrimSuffix(strings.TrimSuffix(n, ".up.sql"), ".down.sql")
		if direction[stem] == nil {
			direction[stem] = map[string]bool{}
		}
		direction[stem][m[2]] = true
		if owner, ok := versionOwner[m[1]]; ok && owner != stem {
			problems = append(problems, n+": version "+m[1]+" is already used by "+owner)
		}
		if _, ok := versionOwner[m[1]]; !ok {
			versionOwner[m[1]] = stem
		}
	}
	for stem, d := range direction {
		if !d["up"] {
			problems = append(problems, stem+": missing .up.sql")
		}
		if !d["down"] {
			problems = append(problems, stem+": missing .down.sql")
		}
	}
	return problems
}

func TestMigrationsAreWellFormed(t *testing.T) {
	dir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == "README.md" {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Fatal("no migrations found")
	}
	for _, p := range migrationProblems(names) {
		t.Error(p)
	}
}

func TestMigrationRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  int
	}{
		{"valid pair", []string{"20260101000000_location_create_tables.up.sql", "20260101000000_location_create_tables.down.sql"}, 0},
		{"old six digit number", []string{"000005_create_locations_tables.up.sql", "000005_create_locations_tables.down.sql"}, 2},
		{"missing module part", []string{"20260101000000_create.up.sql", "20260101000000_create.down.sql"}, 2},
		{"uppercase", []string{"20260101000000_Location_create.up.sql"}, 1},
		{"up without down", []string{"20260101000000_location_create_tables.up.sql"}, 1},
		{"down without up", []string{"20260101000000_location_create_tables.down.sql"}, 1},
		{"duplicate version", []string{
			"20260101000000_location_create_tables.up.sql", "20260101000000_location_create_tables.down.sql",
			"20260101000000_media_create_table.up.sql", "20260101000000_media_create_table.down.sql",
		}, 2},
		{"wrong extension", []string{"20260101000000_location_create_tables.sql"}, 1},
	}
	for _, c := range cases {
		if got := migrationProblems(c.files); len(got) != c.want {
			t.Errorf("%s: %d problems %v, want %d", c.name, len(got), got, c.want)
		}
	}
}
