package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazhedho/logus"

	"starter-kit/internal/testutil/logcapture"
)

func writeAppEnv(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.env"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONSUL", "")
	t.Setenv("APP_CONFIG", dir)
	t.Setenv("APP_ENV", "test")
}

func TestLoadRemoteExportsTheConfigFile(t *testing.T) {
	writeAppEnv(t, "CONFIG_ID=remote-file\nREMOTE_FLAG=on\nREMOTE_INT=42\n")
	t.Setenv("CONFIG_ID", "")
	t.Setenv("REMOTE_FLAG", "")
	t.Setenv("REMOTE_INT", "")

	LoadRemote()

	for key, want := range map[string]string{"REMOTE_FLAG": "on", "REMOTE_INT": "42", "CONFIG_ID": "remote-file"} {
		if got := os.Getenv(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestLoadRemoteDoesNotOverrideTheEnvironment(t *testing.T) {
	writeAppEnv(t, "KEPT_BY_ENV=from-file\nFILLED_FROM_FILE=from-file\nBLANK_IN_ENV=from-file\n")
	t.Setenv("KEPT_BY_ENV", "from-env")
	t.Setenv("BLANK_IN_ENV", "  ")
	t.Setenv("FILLED_FROM_FILE", "")
	if err := os.Unsetenv("FILLED_FROM_FILE"); err != nil {
		t.Fatal(err)
	}

	LoadRemote()

	if got := os.Getenv("KEPT_BY_ENV"); got != "from-env" {
		t.Fatalf("KEPT_BY_ENV = %q: the environment must win over remote config", got)
	}
	if got := os.Getenv("FILLED_FROM_FILE"); got != "from-file" {
		t.Fatalf("FILLED_FROM_FILE = %q, want the file value for an unset variable", got)
	}
	if got := os.Getenv("BLANK_IN_ENV"); got != "from-file" {
		t.Fatalf("BLANK_IN_ENV = %q, want the file value for a blank variable", got)
	}
	t.Cleanup(func() { _ = os.Unsetenv("FILLED_FROM_FILE") })
}

func TestLoadRemoteSkipsAConfigAlreadyApplied(t *testing.T) {
	writeAppEnv(t, "CONFIG_ID=same\nSKIPPED_FLAG=on\n")
	t.Setenv("CONFIG_ID", "same")
	t.Setenv("SKIPPED_FLAG", "")
	if err := os.Unsetenv("SKIPPED_FLAG"); err != nil {
		t.Fatal(err)
	}

	LoadRemote()

	if _, ok := os.LookupEnv("SKIPPED_FLAG"); ok {
		t.Fatal("a config whose CONFIG_ID is already applied must not be exported again")
	}
}

func TestLoadRemoteLogsAMissingFileAtDebugOnly(t *testing.T) {
	t.Setenv("CONSUL", "")
	t.Setenv("APP_CONFIG", "")
	t.Setenv("APP_ENV", "no-such-env")
	t.Chdir(t.TempDir())

	capture := logcapture.Start()
	defer capture.Stop()
	logus.SetLevel(logus.LevelInfo)
	t.Cleanup(func() { logus.SetLevel(logus.LevelInfo) })

	LoadRemote()
	if got := capture.All(); strings.Contains(got, "no-such-env") {
		t.Fatalf("a missing config file must not be logged above debug: %s", got)
	}

	logus.SetLevel(logus.LevelDebug)
	mark := capture.Mark()
	LoadRemote()
	if got := capture.Since(mark); !strings.Contains(got, "no-such-env") {
		t.Fatalf("a missing config file must be logged at debug, got: %q", got)
	}
}
