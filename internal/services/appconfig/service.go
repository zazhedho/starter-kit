package serviceappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/internal/dto"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	"starter-kit/pkg/filter"
	"time"
)

type AppConfigService struct {
	Repo interfaceappconfig.RepoAppConfigInterface
}

func NewAppConfigService(repo interfaceappconfig.RepoAppConfigInterface) *AppConfigService {
	return &AppConfigService{Repo: repo}
}

func (s *AppConfigService) GetAll(params filter.BaseParams) ([]domainappconfig.AppConfig, int64, error) {
	return s.Repo.GetAll(params)
}

func (s *AppConfigService) GetByID(id string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByID(id)
}

func (s *AppConfigService) Update(id string, req dto.UpdateAppConfig) (domainappconfig.AppConfig, error) {
	config, err := s.Repo.GetByID(id)
	if err != nil {
		return domainappconfig.AppConfig{}, err
	}

	config.Value = req.Value
	if req.IsActive != nil {
		config.IsActive = *req.IsActive
	}
	config.UpdatedAt = new(time.Now())

	if err := s.Repo.Update(config); err != nil {
		return domainappconfig.AppConfig{}, err
	}

	return config, nil
}

var _ interfaceappconfig.ServiceAppConfigInterface = (*AppConfigService)(nil)
