package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zazhedho/authkit/authutil"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

// LoadRemote applies the optional remote or file configuration: Consul when
// CONSUL is set, otherwise the file named by APP_CONFIG (or config/<APP_ENV>.env).
// Whatever it finds is exported to the process environment unless CONFIG_ID
// shows the same version was already applied; FromEnv then reads the result.
// A missing source is logged and ignored. Call it once, before FromEnv.
func LoadRemote() {
	confID := getAppConf("CONFIG_ID", "", nil)
	logus.WriteLog(logus.LogLevelDebug, fmt.Sprintf("ConfigID: %v", confID))
}

func getAppConf(key string, def any, rdbCache *redis.Client) any {
	cacheKey := authutil.RedisAppConf
	var appConf map[string]string
	var cache, getNewConfig bool

	if consul := utils.GetEnv("CONSUL", ""); consul != "" {
		appConf, cache, getNewConfig = loadConsulConfig(consul, rdbCache, cacheKey)
	} else {
		appConf = loadFileConfig()
	}

	applyAppConfig(appConf, cache, getNewConfig, rdbCache, cacheKey)
	return utils.GetEnv(key, def)
}

func loadConsulConfig(consul string, client *redis.Client, cacheKey string) (map[string]string, bool, bool) {
	appConf := make(map[string]string)
	cache := utils.NormalizeKey(utils.GetEnv("CACHE", "")) == "on" && client != nil
	getNewConfig := !cache

	if cache {
		cachedConfig, err := client.Get(context.Background(), cacheKey).Result()
		if err == nil {
			if err := json.Unmarshal([]byte(cachedConfig), &appConf); err != nil {
				logus.WriteLog(logus.LogLevelError, fmt.Sprintf("utils.GetAppConf; Unmarshal conf from cache; %s; error: %+v;", cachedConfig, err))
				getNewConfig = true
			}
		} else if errors.Is(err, redis.Nil) {
			getNewConfig = true
		}
	}

	if getNewConfig {
		loadConsulRemoteConfig(consul, appConf)
	}
	return appConf, cache, getNewConfig
}

func loadConsulRemoteConfig(consul string, appConf map[string]string) {
	consulPath := fmt.Sprintf("%s/%s", utils.GetEnv("CONSUL_PATH", ""), utils.GetEnv("APP_ENV", ""))
	runtimeViper := viper.New()
	if err := runtimeViper.AddRemoteProvider("consul", consul, consulPath); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("utils.GetAppConf; AddRemoteProvider: %s/%s; error: %+v;", consul, consulPath, err))
	}
	runtimeViper.SetConfigType("json")
	if err := runtimeViper.ReadRemoteConfig(); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("utils.GetAppConf; Loading config: %s/%s; error: %+v;", consul, consulPath, err))
	} else if err := runtimeViper.Unmarshal(&appConf); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("utils.GetAppConf; Loading congif: %s/%s; error: unable to decode into map, %+v;", consul, consulPath, err))
	}
}

func loadFileConfig() map[string]string {
	appConf := make(map[string]string)
	configName := "app"
	pathConfig := utils.GetEnv("APP_CONFIG", "")
	if pathConfig == "" {
		pathConfig = "config"
		configName = utils.GetEnv("APP_ENV", "")
	}

	viper.AddConfigPath(pathConfig)
	viper.SetConfigType("env")
	viper.SetConfigName(configName)
	if err := viper.ReadInConfig(); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("utils.GetAppConf; Loading config: %s - %s.env; error:  %+v;", pathConfig, configName, err))
	} else {
		_ = viper.Unmarshal(&appConf)
	}
	return appConf
}

func applyAppConfig(appConf map[string]string, cache, getNewConfig bool, client *redis.Client, cacheKey string) {
	if len(appConf) == 0 {
		return
	}
	if _, ok := appConf["config_id"]; !ok {
		appConf["config_id"] = uuid.NewString()
	}
	if appConf["config_id"] != utils.GetEnv("CONFIG_ID", "") {
		for key, value := range appConf {
			if err := os.Setenv(utils.NormalizeUpperKey(key), value); err != nil {
				logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to set app config %s: %v", key, err))
			}
		}
	}
	if cache && getNewConfig {
		go func() {
			if cacheData, err := json.Marshal(appConf); err == nil {
				ttl := utils.GetEnv("TTL_CACHE_CONFIG_APP", time.Duration(60*60*24)) * time.Second
				_ = client.Set(context.Background(), cacheKey, string(cacheData), ttl).Err()
			}
		}()
	}
}
