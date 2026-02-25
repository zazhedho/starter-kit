package interfaceaudit

import domainaudit "starter-kit/internal/domain/audit"

type ServiceAuditInterface interface {
	Store(req domainaudit.AuditEvent) error
}
