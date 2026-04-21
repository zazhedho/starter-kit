package serviceappconfig

import (
	"context"
	"errors"
	domainappconfig "starter-kit/internal/domain/appconfig"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
	"testing"
	"time"

	"gorm.io/gorm"
)

type appConfigRepoMock struct {
	byID   domainappconfig.AppConfig
	byKey  map[string]domainappconfig.AppConfig
	update domainappconfig.AppConfig
	getErr error
	keyErr error
	list   []domainappconfig.AppConfig
	total  int64
}

func (m *appConfigRepoMock) Store(ctx context.Context, data domainappconfig.AppConfig) error {
	return nil
}
func (m *appConfigRepoMock) GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error) {
	if m.getErr != nil {
		return domainappconfig.AppConfig{}, m.getErr
	}
	return m.byID, nil
}
func (m *appConfigRepoMock) GetAll(ctx context.Context, params filter.BaseParams) ([]domainappconfig.AppConfig, int64, error) {
	return append([]domainappconfig.AppConfig{}, m.list...), m.total, nil
}
func (m *appConfigRepoMock) Update(ctx context.Context, data domainappconfig.AppConfig) error {
	m.update = data
	m.byID = data
	return nil
}
func (m *appConfigRepoMock) Delete(ctx context.Context, id string) error { return nil }
func (m *appConfigRepoMock) GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error) {
	if m.keyErr != nil {
		return domainappconfig.AppConfig{}, m.keyErr
	}
	config, ok := m.byKey[configKey]
	if !ok {
		return domainappconfig.AppConfig{}, gorm.ErrRecordNotFound
	}
	return config, nil
}

func TestGetBoolReturnsDefaultWhenConfigMissing(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{byKey: map[string]domainappconfig.AppConfig{}})

	value, err := service.GetBool(context.Background(), "feature.example", true)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !value {
		t.Fatalf("expected fallback true, got false")
	}
}

func TestGetBoolReturnsDefaultWhenConfigInactive(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{
		byKey: map[string]domainappconfig.AppConfig{
			"feature.example": {ConfigKey: "feature.example", Value: "false", IsActive: false},
		},
	})

	value, err := service.GetBool(context.Background(), "feature.example", true)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !value {
		t.Fatalf("expected fallback true, got false")
	}
}

func TestGetBoolParsesFeatureFlagValue(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{
		byKey: map[string]domainappconfig.AppConfig{
			"feature.example": {ConfigKey: "feature.example", Value: "enabled", IsActive: true},
		},
	})

	value, err := service.GetBool(context.Background(), "feature.example", false)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !value {
		t.Fatalf("expected true, got false")
	}
}

func TestGetIntReturnsParseErrorForInvalidValue(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{
		byKey: map[string]domainappconfig.AppConfig{
			"jobs.batch_size": {ConfigKey: "jobs.batch_size", Value: "abc", IsActive: true},
		},
	})

	_, err := service.GetInt(context.Background(), "jobs.batch_size", 10)
	if err == nil {
		t.Fatalf("expected parse error, got nil")
	}
}

func TestGetDurationParsesValue(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{
		byKey: map[string]domainappconfig.AppConfig{
			"jobs.interval": {ConfigKey: "jobs.interval", Value: "30m", IsActive: true},
		},
	})

	value, err := service.GetDuration(context.Background(), "jobs.interval", time.Minute)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if value != 30*time.Minute {
		t.Fatalf("expected 30m, got %v", value)
	}
}

func TestDecodeJSONLeavesTargetWhenConfigMissing(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{byKey: map[string]domainappconfig.AppConfig{}})

	target := struct {
		Limit int `json:"limit"`
	}{Limit: 7}

	if err := service.DecodeJSON(context.Background(), "jobs.rules", &target); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if target.Limit != 7 {
		t.Fatalf("expected target unchanged, got %+v", target)
	}
}

func TestDecodeJSONDecodesActiveConfig(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{
		byKey: map[string]domainappconfig.AppConfig{
			"jobs.rules": {ConfigKey: "jobs.rules", Value: `{"limit":5}`, IsActive: true},
		},
	})

	target := struct {
		Limit int `json:"limit"`
	}{}

	if err := service.DecodeJSON(context.Background(), "jobs.rules", &target); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if target.Limit != 5 {
		t.Fatalf("expected limit 5, got %+v", target)
	}
}

func TestGetStringReturnsRepositoryError(t *testing.T) {
	service := NewAppConfigService(&appConfigRepoMock{keyErr: errors.New("db error")})

	_, err := service.GetString(context.Background(), "app.name", "Starter")
	if err == nil || err.Error() != "db error" {
		t.Fatalf("expected db error, got %v", err)
	}
}

func TestUpdateStillWorks(t *testing.T) {
	nowConfig := domainappconfig.AppConfig{Id: "cfg-1", ConfigKey: "feature.example", Value: "old", IsActive: true}
	repo := &appConfigRepoMock{byID: nowConfig}
	service := NewAppConfigService(repo)

	updated, err := service.Update(context.Background(), "cfg-1", dto.UpdateAppConfig{Value: "new"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if updated.Value != "new" || repo.update.Value != "new" {
		t.Fatalf("expected updated value new, got %+v", updated)
	}
}
