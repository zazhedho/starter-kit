package repositoryappconfig

import (
	domainappconfig "starter-kit/internal/domain/appconfig"
	interfaceappconfig "starter-kit/internal/interfaces/appconfig"
	repositorygeneric "starter-kit/internal/repositories/generic"
	"starter-kit/pkg/filter"

	"gorm.io/gorm"
)

type repo struct {
	*repositorygeneric.GenericRepository[domainappconfig.AppConfig]
}

func NewAppConfigRepo(db *gorm.DB) interfaceappconfig.RepoAppConfigInterface {
	return &repo{GenericRepository: repositorygeneric.New[domainappconfig.AppConfig](db)}
}

func (r *repo) GetAll(params filter.BaseParams) (ret []domainappconfig.AppConfig, totalData int64, err error) {
	return r.GenericRepository.GetAll(params, repositorygeneric.QueryOptions{
		Search:          repositorygeneric.BuildSearchFunc("config_key", "display_name", "category"),
		AllowedFilters:  []string{"category", "is_active"},
		FilterSanitizer: filter.WhitelistStringFilter,
		AllowedOrderColumns: []string{
			"config_key",
			"display_name",
			"category",
			"is_active",
			"created_at",
			"updated_at",
		},
		DefaultOrders: []string{"category ASC", "display_name ASC"},
	})
}

func (r *repo) GetByKey(configKey string) (ret domainappconfig.AppConfig, err error) {
	return r.GetOneByField("config_key", configKey)
}
