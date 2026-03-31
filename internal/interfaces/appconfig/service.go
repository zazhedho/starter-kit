package interfaceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
)

type ServiceAppConfigInterface interface {
	GetAll(params filter.BaseParams) ([]domainappconfig.AppConfig, int64, error)
	GetByID(id string) (domainappconfig.AppConfig, error)
	Update(id string, req dto.UpdateAppConfig) (domainappconfig.AppConfig, error)
}
