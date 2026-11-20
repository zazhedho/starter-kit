package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
)

// LoadRemote exports Consul or config file settings to the environment, but only
// for variables that are unset or blank: the environment wins. A source whose
// CONFIG_ID equals the environment's was applied before. Call it before FromEnv.
func LoadRemote() {
	var appConf map[string]string
	if consul := gokit.GetEnv("CONSUL", ""); consul != "" {
		appConf = loadConsulConfig(consul)
	} else {
		appConf = loadFileConfig()
	}
	applyAppConfig(appConf)
}

// normalizeKey trims and lower-cases a setting name or enum-like value.
func normalizeKey(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

// normalizeUpperKey trims and upper-cases a setting name from the remote source.
func normalizeUpperKey(value string) string { return strings.ToUpper(strings.TrimSpace(value)) }

func loadConsulConfig(consul string) map[string]string {
	appConf := make(map[string]string)
	consulPath := fmt.Sprintf("%s/%s", gokit.GetEnv("CONSUL_PATH", ""), gokit.GetEnv("APP_ENV", ""))
	runtimeViper := viper.New()
	if err := runtimeViper.AddRemoteProvider("consul", consul, consulPath); err != nil {
		logus.Logf(logus.LevelError, "config; AddRemoteProvider: %s/%s; error: %+v;", consul, consulPath, err)
	}
	runtimeViper.SetConfigType("json")
	if err := runtimeViper.ReadRemoteConfig(); err != nil {
		logus.Logf(logus.LevelError, "config; Loading config: %s/%s; error: %+v;", consul, consulPath, err)
	} else if err := runtimeViper.Unmarshal(&appConf); err != nil {
		logus.Logf(logus.LevelError, "config; Loading config: %s/%s; error: unable to decode into map, %+v;", consul, consulPath, err)
	}
	return appConf
}

func loadFileConfig() map[string]string {
	appConf := make(map[string]string)
	configName := "app"
	pathConfig := gokit.GetEnv("APP_CONFIG", "")
	if pathConfig == "" {
		pathConfig = "config"
		configName = gokit.GetEnv("APP_ENV", "")
	}

	fileViper := viper.New()
	fileViper.AddConfigPath(pathConfig)
	fileViper.SetConfigType("env")
	fileViper.SetConfigName(configName)
	if err := fileViper.ReadInConfig(); err != nil {
		// Most projects have no config file; only an unreadable one is a problem.
		level := logus.LevelError
		if _, missing := errors.AsType[viper.ConfigFileNotFoundError](err); missing {
			level = logus.LevelDebug
		}
		logus.Logf(level, "config; Loading config: %s - %s.env; error: %+v;", pathConfig, configName, err)
		return appConf
	}
	if err := fileViper.Unmarshal(&appConf); err != nil {
		logus.Logf(logus.LevelError, "config; Decoding config: %s - %s.env; error: %+v;", pathConfig, configName, err)
	}
	return appConf
}

func applyAppConfig(appConf map[string]string) {
	if id := appConf["config_id"]; id != "" && id == gokit.GetEnv("CONFIG_ID", "") {
		return
	}
	for key, value := range appConf {
		name := normalizeUpperKey(key)
		if current, set := os.LookupEnv(name); set && strings.TrimSpace(current) != "" {
			continue
		}
		if err := os.Setenv(name, value); err != nil {
			logus.Logf(logus.LevelError, "failed to set app config %s: %v", name, err)
		}
	}
}
