package interfaceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	interfacegeneric "starter-kit/internal/interfaces/generic"
)

type RepoAppConfigInterface interface {
	interfacegeneric.GenericRepository[domainappconfig.AppConfig]

	GetByKey(configKey string) (domainappconfig.AppConfig, error)
}
