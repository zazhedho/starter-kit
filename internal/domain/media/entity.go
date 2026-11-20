package media

import (
	"time"

	"gorm.io/gorm"
)

func (Media) TableName() string {
	return "media"
}

type Media struct {
	ID           string         `json:"id" gorm:"column:id;primaryKey"`
	OwnerUserID  string         `json:"owner_user_id" gorm:"column:owner_user_id"`
	ObjectKey    string         `json:"object_key" gorm:"column:object_key"`
	URL          string         `json:"url" gorm:"column:url"`
	OriginalName string         `json:"original_name" gorm:"column:original_name"`
	ContentType  string         `json:"content_type" gorm:"column:content_type"`
	Size         int64          `json:"size" gorm:"column:size"`
	CreatedAt    time.Time      `json:"created_at" gorm:"column:created_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"column:deleted_at"`
}

// Actor is who performs a media operation, reduced to what the rules need, so
// services never import the auth framework. The Can*Any flags carry the
// media:<action>_any permissions: acting on one's own files needs none.
type Actor struct {
	UserID       string
	CanListAny   bool
	CanDeleteAny bool
}
