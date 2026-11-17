package database

import (
	"database/sql"
	"fmt"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnDb() (db *gorm.DB, sqlDB *sql.DB, err error) {
	dsn := utils.GetEnv("DATABASE_URL", "")

	if dsn == "" {
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=Asia/Jakarta",
			utils.GetEnv("DB_HOST", ""),
			utils.GetEnv("DB_PORT", ""),
			utils.GetEnv("DB_USERNAME", ""),
			utils.GetEnv("DB_PASS", ""),
			utils.GetEnv("DB_NAME", ""),
			utils.GetEnv("DB_SSLMODE", "disable"))
	}
	logus.WriteLog(logus.LogLevelDebug, "ConnDb; Initialize db connection...")

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("ConnDb; %s Error: %s", dsn, err.Error()))
		return
	}

	maxIdle := 10
	maxIdleTime := 5 * time.Minute
	maxConn := 100
	maxLifeTime := time.Hour

	sqlDB, err = db.DB()
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("ConnDb.sqlDB; %s Error: %s", dsn, err.Error()))
		return
	}

	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxIdleTime(maxIdleTime)
	sqlDB.SetMaxOpenConns(maxConn)
	sqlDB.SetConnMaxLifetime(maxLifeTime)

	return
}
