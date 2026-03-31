package repositoryappconfig

import (
	"fmt"
	domainappconfig "starter-kit/internal/domain/appconfig"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	"starter-kit/pkg/filter"

	"gorm.io/gorm"
)

type repo struct {
	DB *gorm.DB
}

func NewAppConfigRepo(db *gorm.DB) interfaceappconfig.RepoAppConfigInterface {
	return &repo{DB: db}
}

func (r *repo) GetAll(params filter.BaseParams) (ret []domainappconfig.AppConfig, totalData int64, err error) {
	query := r.DB.Model(&domainappconfig.AppConfig{}).Where("deleted_at IS NULL")

	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		query = query.Where(
			"LOWER(config_key) LIKE LOWER(?) OR LOWER(display_name) LIKE LOWER(?) OR LOWER(category) LIKE LOWER(?)",
			searchPattern,
			searchPattern,
			searchPattern,
		)
	}

	safeFilters := filter.WhitelistStringFilter(params.Filters, []string{"category", "is_active"})
	for key, value := range safeFilters {
		if value == nil {
			continue
		}

		switch v := value.(type) {
		case string:
			if v == "" {
				continue
			}
			query = query.Where(fmt.Sprintf("%s = ?", key), v)
		default:
			query = query.Where(fmt.Sprintf("%s = ?", key), v)
		}
	}

	if err = query.Count(&totalData).Error; err != nil {
		return nil, 0, err
	}

	if params.OrderBy != "" && params.OrderDirection != "" {
		validColumns := map[string]bool{
			"config_key":   true,
			"display_name": true,
			"category":     true,
			"is_active":    true,
			"created_at":   true,
			"updated_at":   true,
		}
		if _, ok := validColumns[params.OrderBy]; !ok {
			return nil, 0, fmt.Errorf("invalid orderBy column: %s", params.OrderBy)
		}
		query = query.Order(fmt.Sprintf("%s %s", params.OrderBy, params.OrderDirection))
	} else {
		query = query.Order("category ASC").Order("display_name ASC")
	}

	if err = query.Offset(params.Offset).Limit(params.Limit).Find(&ret).Error; err != nil {
		return nil, 0, err
	}

	return ret, totalData, nil
}

func (r *repo) GetByID(id string) (ret domainappconfig.AppConfig, err error) {
	err = r.DB.Where("id = ? AND deleted_at IS NULL", id).First(&ret).Error
	return
}

func (r *repo) GetByKey(configKey string) (ret domainappconfig.AppConfig, err error) {
	err = r.DB.Where("config_key = ? AND deleted_at IS NULL", configKey).First(&ret).Error
	return
}

func (r *repo) Update(config domainappconfig.AppConfig) error {
	return r.DB.Save(&config).Error
}
