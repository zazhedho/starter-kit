package interfaceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/pkg/filter"
)

type RepoAppConfigInterface interface {
	GetAll(params filter.BaseParams) ([]domainappconfig.AppConfig, int64, error)
	GetByID(id string) (domainappconfig.AppConfig, error)
	GetByKey(configKey string) (domainappconfig.AppConfig, error)
	Update(config domainappconfig.AppConfig) error
}
