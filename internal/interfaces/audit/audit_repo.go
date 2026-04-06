package interfaceaudit

import (
	domainaudit "starter-kit/internal/domain/audit"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoAuditInterface interface {
	interfacebase.GenericRepository[domainaudit.AuditTrail]
}
