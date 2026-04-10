package repositorylocation

import (
	domainlocation "starter-kit/internal/domain/location"
	interfacelocation "starter-kit/internal/interfaces/location"
	"starter-kit/utils"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type repo struct {
	DB *gorm.DB
}

func NewLocationRepo(db *gorm.DB) interfacelocation.RepoLocationInterface {
	return &repo{DB: db}
}

func (r *repo) ListProvinces() (ret []domainlocation.Province, err error) {
	err = r.DB.Where("deleted_at IS NULL").Order("name ASC").Find(&ret).Error
	return
}

func (r *repo) ListCitiesByProvince(provinceCode string) (ret []domainlocation.City, err error) {
	err = r.DB.Where("province_code = ? AND deleted_at IS NULL", provinceCode).Order("name ASC").Find(&ret).Error
	return
}

func (r *repo) ListDistrictsByCity(cityCode string) (ret []domainlocation.District, err error) {
	err = r.DB.Where("city_code = ? AND deleted_at IS NULL", cityCode).Order("name ASC").Find(&ret).Error
	return
}

func (r *repo) ListVillagesByDistrict(districtCode string) (ret []domainlocation.Village, err error) {
	err = r.DB.Where("district_code = ? AND deleted_at IS NULL", districtCode).Order("name ASC").Find(&ret).Error
	return
}

func (r *repo) GetProvinceByCode(code string) (ret domainlocation.Province, err error) {
	err = r.DB.Where("code = ? AND deleted_at IS NULL", code).First(&ret).Error
	return
}

func (r *repo) GetCityByCode(code string) (ret domainlocation.City, err error) {
	err = r.DB.Where("code = ? AND deleted_at IS NULL", code).First(&ret).Error
	return
}

func (r *repo) GetDistrictByCode(code string) (ret domainlocation.District, err error) {
	err = r.DB.Where("code = ? AND deleted_at IS NULL", code).First(&ret).Error
	return
}

func (r *repo) UpsertProvinces(items []domainlocation.Province) error {
	return r.upsert("code", items)
}

func (r *repo) UpsertCities(items []domainlocation.City) error {
	return r.upsert("code", items)
}

func (r *repo) UpsertDistricts(items []domainlocation.District) error {
	return r.upsert("code", items)
}

func (r *repo) UpsertVillages(items []domainlocation.Village) error {
	return r.upsert("code", items)
}

func (r *repo) CreateSyncJob(job *domainlocation.SyncJob) error {
	return r.DB.Create(job).Error
}

func (r *repo) UpdateSyncJob(job *domainlocation.SyncJob) error {
	return r.DB.Save(job).Error
}

func (r *repo) GetSyncJobByID(id string) (ret domainlocation.SyncJob, err error) {
	err = r.DB.Where("id = ?", id).First(&ret).Error
	return
}

func (r *repo) GetActiveSyncJob() (ret domainlocation.SyncJob, err error) {
	err = r.DB.
		Where("status IN ?", []string{"queued", "running"}).
		Order("created_at ASC").
		First(&ret).Error
	return
}

func (r *repo) FailActiveSyncJobs(message string) error {
	now := time.Now()
	return r.DB.Model(&domainlocation.SyncJob{}).
		Where("status IN ?", []string{"queued", "running"}).
		Updates(map[string]interface{}{
			"status":        "failed",
			"message":       "Location sync interrupted",
			"error_message": message,
			"finished_at":   now,
			"updated_at":    now,
		}).Error
}

func (r *repo) upsert(conflictColumn string, values interface{}) error {
	now := time.Now()

	switch items := values.(type) {
	case []domainlocation.Province:
		for i := range items {
			if items[i].ID == "" {
				items[i].ID = utils.CreateUUID()
			}
			if items[i].CreatedAt.IsZero() {
				items[i].CreatedAt = now
			}
			items[i].UpdatedAt = &now
		}
		return r.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: conflictColumn}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "updated_at", "deleted_at"}),
		}).Create(&items).Error
	case []domainlocation.City:
		for i := range items {
			if items[i].ID == "" {
				items[i].ID = utils.CreateUUID()
			}
			if items[i].CreatedAt.IsZero() {
				items[i].CreatedAt = now
			}
			items[i].UpdatedAt = &now
		}
		return r.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: conflictColumn}},
			DoUpdates: clause.AssignmentColumns([]string{"province_code", "name", "updated_at", "deleted_at"}),
		}).Create(&items).Error
	case []domainlocation.District:
		for i := range items {
			if items[i].ID == "" {
				items[i].ID = utils.CreateUUID()
			}
			if items[i].CreatedAt.IsZero() {
				items[i].CreatedAt = now
			}
			items[i].UpdatedAt = &now
		}
		return r.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: conflictColumn}},
			DoUpdates: clause.AssignmentColumns([]string{"city_code", "name", "updated_at", "deleted_at"}),
		}).Create(&items).Error
	case []domainlocation.Village:
		for i := range items {
			if items[i].ID == "" {
				items[i].ID = utils.CreateUUID()
			}
			if items[i].CreatedAt.IsZero() {
				items[i].CreatedAt = now
			}
			items[i].UpdatedAt = &now
		}
		return r.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: conflictColumn}},
			DoUpdates: clause.AssignmentColumns([]string{"district_code", "name", "updated_at", "deleted_at"}),
		}).Create(&items).Error
	default:
		return nil
	}
}
