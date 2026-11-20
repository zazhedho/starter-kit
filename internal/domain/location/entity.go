package location

import (
	"time"

	"gorm.io/gorm"
)

type Province struct {
	ID        string         `json:"id" gorm:"column:id;primaryKey"`
	Code      string         `json:"code" gorm:"column:code"`
	Name      string         `json:"name" gorm:"column:name"`
	CreatedAt time.Time      `json:"created_at" gorm:"column:created_at"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"column:deleted_at"`
}

func (Province) TableName() string {
	return "provinces"
}

type City struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey"`
	Code         string         `json:"code" gorm:"column:code"`
	ProvinceCode string         `json:"province_code" gorm:"column:province_code"`
	Name         string         `json:"name" gorm:"column:name"`
	CreatedAt    time.Time      `json:"created_at" gorm:"column:created_at"`
	UpdatedAt    *time.Time     `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"column:deleted_at"`
}

func (City) TableName() string {
	return "cities"
}

type District struct {
	ID        string         `json:"id" gorm:"column:id;primaryKey"`
	Code      string         `json:"code" gorm:"column:code"`
	CityCode  string         `json:"city_code" gorm:"column:city_code"`
	Name      string         `json:"name" gorm:"column:name"`
	CreatedAt time.Time      `json:"created_at" gorm:"column:created_at"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"column:deleted_at"`
}

func (District) TableName() string {
	return "districts"
}

type Village struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey"`
	Code         string         `json:"code" gorm:"column:code"`
	DistrictCode string         `json:"district_code" gorm:"column:district_code"`
	Name         string         `json:"name" gorm:"column:name"`
	CreatedAt    time.Time      `json:"created_at" gorm:"column:created_at"`
	UpdatedAt    *time.Time     `json:"updated_at,omitempty" gorm:"column:updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"column:deleted_at"`
}

func (Village) TableName() string {
	return "villages"
}

type SyncJob struct {
	ID            string     `json:"id" gorm:"column:id;primaryKey"`
	Status        string     `json:"status" gorm:"column:status"`
	Level         string     `json:"level" gorm:"column:level"`
	ProvinceCode  string     `json:"province_code,omitempty" gorm:"column:province_code"`
	CityCode      string     `json:"city_code,omitempty" gorm:"column:city_code"`
	DistrictCode  string     `json:"district_code,omitempty" gorm:"column:district_code"`
	RequestedBy   string     `json:"requested_by_user_id" gorm:"column:requested_by_user_id"`
	Message       string     `json:"message,omitempty" gorm:"column:message"`
	ErrorMessage  string     `json:"error_message,omitempty" gorm:"column:error_message"`
	ProvinceCount int        `json:"province_count" gorm:"column:province_count"`
	CityCount     int        `json:"city_count" gorm:"column:city_count"`
	DistrictCount int        `json:"district_count" gorm:"column:district_count"`
	VillageCount  int        `json:"village_count" gorm:"column:village_count"`
	StartedAt     *time.Time `json:"started_at,omitempty" gorm:"column:started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty" gorm:"column:finished_at"`
	CreatedAt     time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty" gorm:"column:updated_at"`

	// OwnerInstanceID names the service instance running the job; HeartbeatAt is
	// the last time that instance reported in. A job whose heartbeat is stale
	// belongs to a dead instance and may be taken over.
	OwnerInstanceID string    `json:"-" gorm:"column:owner_instance_id"`
	HeartbeatAt     time.Time `json:"-" gorm:"column:heartbeat_at"`
}

func (SyncJob) TableName() string {
	return "location_sync_jobs"
}

// SyncProgress is what a running sync job reports: a message and how many rows
// of each level it has stored so far.
type SyncProgress struct {
	Message       string
	ProvinceCount int
	CityCount     int
	DistrictCount int
	VillageCount  int
}

// SyncFinish is the final state of a sync job.
type SyncFinish struct {
	Status       string // "completed" or "failed"
	Message      string
	ErrorMessage string
}
