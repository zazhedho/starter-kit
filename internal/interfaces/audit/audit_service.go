package interfaceaudit

import (
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/internal/dto"
	"starter-kit/pkg/filter"
)

type ServiceAuditInterface interface {
	Store(req domainaudit.AuditEvent) error
	GetAll(params filter.BaseParams) ([]dto.AuditTrailResponse, int64, error)
	GetByID(id string) (dto.AuditTrailResponse, error)
}
