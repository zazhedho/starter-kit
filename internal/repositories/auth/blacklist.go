package repositoryauth

import (
	domainauth "starter-kit/internal/domain/auth"
	interfaceauth "starter-kit/internal/interfaces/auth"

	"gorm.io/gorm"
)

type blacklistRepo struct {
	DB *gorm.DB
}

func NewBlacklistRepo(db *gorm.DB) interfaceauth.RepoAuthInterface {
	return &blacklistRepo{
		DB: db,
	}
}

func (r *blacklistRepo) Store(blacklist domainauth.Blacklist) error {
	return r.DB.Create(&blacklist).Error
}

func (r *blacklistRepo) GetByToken(token string) (domainauth.Blacklist, error) {
	var blacklist domainauth.Blacklist
	err := r.DB.Where("token = ?", token).First(&blacklist).Error
	return blacklist, err
}

func (r *blacklistRepo) ExistsByToken(token string) (bool, error) {
	var count int64
	if err := r.DB.Model(&domainauth.Blacklist{}).Where("token = ?", token).Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}
