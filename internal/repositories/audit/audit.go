package repositoryaudit

import (
	domainaudit "starter-kit/internal/domain/audit"
	interfaceaudit "starter-kit/internal/interfaces/audit"

	"gorm.io/gorm"
)

type repo struct {
	DB *gorm.DB
}

func NewAuditRepo(db *gorm.DB) interfaceaudit.RepoAuditInterface {
	return &repo{DB: db}
}

func (r *repo) Store(m domainaudit.AuditTrail) error {
	return r.DB.Create(&m).Error
}
