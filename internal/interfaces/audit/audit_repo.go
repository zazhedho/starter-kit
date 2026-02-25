package interfaceaudit

import domainaudit "starter-kit/internal/domain/audit"

type RepoAuditInterface interface {
	Store(m domainaudit.AuditTrail) error
}
