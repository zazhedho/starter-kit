package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvMissingFileNeedsAppEnv(t *testing.T) {
	missing := filepath.Join(t.TempDir(), ".env")

	t.Setenv("APP_ENV", "")
	if err := LoadDotEnv(missing); err == nil {
		t.Fatal("expected an error: no file and no APP_ENV")
	}

	t.Setenv("APP_ENV", "production")
	if err := LoadDotEnv(missing); err != nil {
		t.Fatalf("APP_ENV is set, a missing file is fine: %v", err)
	}
}

func TestLoadDotEnvDoesNotOverrideExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("DOTENV_TEST_KEEP=from-file\nDOTENV_TEST_NEW=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_TEST_KEEP", "from-env")
	t.Setenv("DOTENV_TEST_NEW", "")
	_ = os.Unsetenv("DOTENV_TEST_NEW")

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("DOTENV_TEST_KEEP"); got != "from-env" {
		t.Errorf("existing variable overridden: %q", got)
	}
	if got := os.Getenv("DOTENV_TEST_NEW"); got != "from-file" {
		t.Errorf("new variable not loaded: %q", got)
	}
}
