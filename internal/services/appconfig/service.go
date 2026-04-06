package serviceappconfig

import (
	"errors"
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/internal/dto"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	"starter-kit/pkg/configvalue"
	"starter-kit/pkg/filter"
	"time"

	"gorm.io/gorm"
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

func (s *AppConfigService) GetByKey(configKey string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByKey(configKey)
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

func (s *AppConfigService) GetString(configKey string, fallback string) (string, error) {
	config, found, err := s.getActiveConfigByKey(configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return configvalue.String(config.Value, fallback), nil
}

func (s *AppConfigService) GetBool(configKey string, fallback bool) (bool, error) {
	config, found, err := s.getActiveConfigByKey(configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return configvalue.Bool(config.Value, fallback)
}

func (s *AppConfigService) GetInt(configKey string, fallback int) (int, error) {
	config, found, err := s.getActiveConfigByKey(configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return configvalue.Int(config.Value, fallback)
}

func (s *AppConfigService) GetDuration(configKey string, fallback time.Duration) (time.Duration, error) {
	config, found, err := s.getActiveConfigByKey(configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return configvalue.Duration(config.Value, fallback)
}

func (s *AppConfigService) DecodeJSON(configKey string, target interface{}) error {
	config, found, err := s.getActiveConfigByKey(configKey)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return configvalue.JSON(config.Value, target)
}

func (s *AppConfigService) IsEnabled(configKey string, fallback bool) (bool, error) {
	return s.GetBool(configKey, fallback)
}

func (s *AppConfigService) getActiveConfigByKey(configKey string) (domainappconfig.AppConfig, bool, error) {
	config, err := s.Repo.GetByKey(configKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domainappconfig.AppConfig{}, false, nil
		}
		return domainappconfig.AppConfig{}, false, err
	}
	if !config.IsActive {
		return domainappconfig.AppConfig{}, false, nil
	}
	return config, true, nil
}

var _ interfaceappconfig.ServiceAppConfigInterface = (*AppConfigService)(nil)
