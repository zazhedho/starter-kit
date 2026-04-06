package interfaceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
	"time"
)

type ServiceAppConfigInterface interface {
	GetAll(params filter.BaseParams) ([]domainappconfig.AppConfig, int64, error)
	GetByID(id string) (domainappconfig.AppConfig, error)
	GetByKey(configKey string) (domainappconfig.AppConfig, error)
	Update(id string, req dto.UpdateAppConfig) (domainappconfig.AppConfig, error)
	GetString(configKey string, fallback string) (string, error)
	GetBool(configKey string, fallback bool) (bool, error)
	GetInt(configKey string, fallback int) (int, error)
	GetDuration(configKey string, fallback time.Duration) (time.Duration, error)
	DecodeJSON(configKey string, target interface{}) error
	IsEnabled(configKey string, fallback bool) (bool, error)
}
