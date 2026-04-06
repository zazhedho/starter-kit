package repositoryaudit

import (
	domainaudit "starter-kit/internal/domain/audit"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	repositorybase "starter-kit/internal/repositories/base"
	"starter-kit/pkg/filter"

	"gorm.io/gorm"
)

type repo struct {
	*repositorybase.GenericRepository[domainaudit.AuditTrail]
}

func NewAuditRepo(db *gorm.DB) interfaceaudit.RepoAuditInterface {
	return &repo{GenericRepository: repositorybase.New[domainaudit.AuditTrail](db)}
}

func (r *repo) GetAll(params filter.BaseParams) (ret []domainaudit.AuditTrail, totalData int64, err error) {
	return r.GenericRepository.GetAll(params, repositorybase.QueryOptions{
		Search:         repositorybase.BuildSearchFunc("action", "resource", "status", "actor_role", "message", "error_message", "request_id", "ip_address"),
		AllowedFilters: []string{"actor_user_id", "actor_role", "action", "resource", "status", "request_id"},
		AllowedOrderColumns: []string{
			"occurred_at",
			"created_at",
			"action",
			"resource",
			"status",
			"actor_role",
		},
		DefaultOrders: []string{"occurred_at DESC", "created_at DESC"},
	})
}
