package interfaceaudit

import (
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/pkg/filter"
)

type ServiceAuditInterface interface {
	Store(req domainaudit.AuditEvent) error
	GetAll(params filter.BaseParams) ([]domainaudit.AuditTrail, int64, error)
	GetByID(id string) (domainaudit.AuditTrail, error)
}
