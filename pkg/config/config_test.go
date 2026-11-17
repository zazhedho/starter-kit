package config

import (
	"os"
	"path/filepath"
	"testing"

	redismock "github.com/go-redis/redismock/v9"
	"github.com/spf13/viper"
)

func TestGetAppConfReturnsDefaultWhenConfigMissing(t *testing.T) {
	viper.Reset()
	t.Setenv("CONSUL", "")
	t.Setenv("APP_CONFIG", t.TempDir())
	t.Setenv("APP_ENV", "test")

	if got := GetAppConf("MISSING_VALUE", "fallback", nil); got != "fallback" {
		t.Fatalf("expected fallback value, got %v", got)
	}
}

func TestGetAppConfLoadsLocalEnvFileAndExportsValues(t *testing.T) {
	viper.Reset()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "app.env")
	if err := os.WriteFile(configPath, []byte("CONFIG_ID=file-config\nFEATURE_FLAG=enabled\nFEATURE_INT=42\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONSUL", "")
	t.Setenv("APP_CONFIG", dir)
	t.Setenv("APP_ENV", "test")
	t.Setenv("CONFIG_ID", "old-config")

	if got := GetAppConf("FEATURE_FLAG", "fallback", nil); got != "enabled" {
		t.Fatalf("expected value from config file, got %v", got)
	}
	if got := os.Getenv("FEATURE_INT"); got != "42" {
		t.Fatalf("expected config value exported to env, got %q", got)
	}
}

func TestGetAppConfUsesCachedConsulConfig(t *testing.T) {
	viper.Reset()
	client, mock := redismock.NewClientMock()
	t.Setenv("CONSUL", "127.0.0.1:8500")
	t.Setenv("CONSUL_PATH", "starter")
	t.Setenv("APP_ENV", "test")
	t.Setenv("CACHE", "on")
	t.Setenv("CONFIG_ID", "old-config")

	mock.ExpectGet("cache:config:app").SetVal(`{"config_id":"cached-config","feature_flag":"cached"}`)
	if got := GetAppConf("FEATURE_FLAG", "fallback", client); got != "cached" {
		t.Fatalf("expected cached config value, got %v", got)
	}
	if got := os.Getenv("CONFIG_ID"); got != "cached-config" {
		t.Fatalf("expected cached config exported to env, got %q", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}
