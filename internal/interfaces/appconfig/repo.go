package interfaceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoAppConfigInterface interface {
	interfacebase.GenericRepository[domainappconfig.AppConfig]

	GetByKey(configKey string) (domainappconfig.AppConfig, error)
}
