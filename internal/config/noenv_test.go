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
	allowed := map[string]bool{
		filepath.Join("pkg", "config", "app_conf.go"): true,
	}
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
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[path] {
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
