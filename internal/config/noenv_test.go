package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEnvReadsOutsideConfig keeps environment access in one place.
func TestNoEnvReadsOutsideConfig(t *testing.T) {
	root := filepath.Join("..", "..")
	banned := []string{"GetEnv(", "DurationFromEnv(", "os.Getenv(", "os.LookupEnv("}

	repo := os.DirFS(root)
	err := fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch {
			case d.Name() == ".git" || d.Name() == ".superpowers":
				return fs.SkipDir
			case path == filepath.Join("internal", "config"):
				return fs.SkipDir
			case path == filepath.Join("internal", "testutil"):
				return fs.SkipDir // test helpers read test-only variables such as STARTER_KIT_TEST_DATABASE_URL
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		for _, b := range banned {
			if strings.Contains(string(data), b) {
				t.Errorf("%s reads the environment with %s", path, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSingleConfigPackage: the Consul/file loader lives in internal/config
// too, so there is no second package that reads the environment.
func TestSingleConfigPackage(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "pkg", "config")); err == nil {
		t.Fatal("pkg/config still exists; the loader belongs in internal/config")
	}
}
