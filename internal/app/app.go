// Package app holds the service startup sequence shared by every entrypoint.
package app

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // Register the PostgreSQL migration driver.
	_ "github.com/golang-migrate/migrate/v4/source/file"       // Register the file-based migration source.
	"github.com/joho/godotenv"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/authkit/mailer"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"

	"starter-kit/infrastructure/database"
	"starter-kit/internal/router"
	"starter-kit/pkg/config"
)

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

// Run loads configuration, connects dependencies, migrates when asked, mounts
// all routes, and serves until the process exits.
func Run() {
	var (
		err        error
		sqlDb      *sql.DB
		runMigrate bool
	)
	if timeZone, err := time.LoadLocation("Asia/Jakarta"); err != nil {
		logus.WriteLog(logus.LogLevelError, "time.LoadLocation - Error: "+err.Error())
	} else {
		time.Local = timeZone
	}

	if err = godotenv.Load(".env"); err != nil && os.Getenv("APP_ENV") == "" {
		log.Fatalf("Error app environment")
	}

	myAddr := "unknown"
	addrs, _ := net.InterfaceAddrs()
	for _, address := range addrs {
		if ipNet, ok := address.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				myAddr = ipNet.IP.String()
				break
			}
		}
	}

	myAddr += strings.Repeat(" ", 15-len(myAddr))
	FailOnError(os.Setenv("ServerIP", myAddr), "Failed to set server IP")
	logus.WriteLog(logus.LogLevelInfo, "Server IP: "+myAddr)

	var port, appName string
	flag.StringVar(&port, "port", os.Getenv("PORT"), "port of the service")
	flag.StringVar(&appName, "appname", os.Getenv("APP_NAME"), "service name")
	flag.BoolVar(&runMigrate, "migrate", utils.GetEnv("RUN_MIGRATION", true), "run database migration before starting server")
	flag.Parse()
	logus.WriteLog(logus.LogLevelInfo, "APP: "+appName+"; PORT: "+port)

	confID := config.GetAppConf("CONFIG_ID", "", nil)
	logus.WriteLog(logus.LogLevelDebug, fmt.Sprintf("ConfigID: %s", confID))
	FailOnError(config.ValidateStartupConfig(port), "Invalid app configuration")

	// Initialize Redis for session management (optional)
	redisClient, err := database.InitRedis()
	if err != nil {
		logus.WriteLog(logus.LogLevelDebug, "Redis not available, session management will be disabled")
	} else {
		defer func() {
			if closeErr := database.CloseRedis(); closeErr != nil {
				logus.WriteLog(logus.LogLevelError, "Failed to close redis connection: "+closeErr.Error())
			}
		}()
		logus.WriteLog(logus.LogLevelInfo, "Redis initialized, session management enabled")
	}

	routes := router.NewRoutes()

	routes.DB, sqlDb, err = database.ConnDb()
	FailOnError(err, "Failed to open db")
	defer func() {
		if closeErr := sqlDb.Close(); closeErr != nil {
			logus.WriteLog(logus.LogLevelError, "Failed to close database connection: "+closeErr.Error())
		}
	}()

	authCfg := authkit.ConfigFromEnv()
	authCfg.DB = routes.DB
	if redisClient != nil {
		authCfg.Redis = redisClient
		// The mailer is only useful with Redis (OTP and password reset need it).
		if sender, mailErr := mailer.NewBrevoSenderFromEnv(); mailErr != nil {
			logus.WriteLog(logus.LogLevelWarn, "Email sender not configured: ", mailErr)
		} else {
			authCfg.Mailer = sender
		}
	}
	kit, err := authkit.New(authCfg)
	FailOnError(err, "Failed to initialize authkit")
	routes.Kit = kit

	if runMigrate {
		// authkit tables first: project migrations may reference users and roles.
		FailOnError(kit.Migrate(context.Background()), "Failed to migrate core tables")
		runMigration()
	}

	routes.MountAuthKit()
	routes.LocationRoutes()
	FailOnError(routes.MediaRoutes(), "Failed to initialize media routes")

	logus.WriteLog(logus.LogLevelInfo, "All routes registered successfully")

	err = routes.App.Run(fmt.Sprintf(":%s", port))
	FailOnError(err, "Failed run service")
}

func runMigration() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			utils.GetEnv("DB_USERNAME", ""),
			utils.GetEnv("DB_PASS", ""),
			utils.GetEnv("DB_HOST", ""),
			utils.GetEnv("DB_PORT", ""),
			utils.GetEnv("DB_NAME", ""),
			utils.GetEnv("DB_SSLMODE", "disable"))
	}

	m, err := migrate.New(utils.GetEnv("PATH_MIGRATE", "file://migrations"), dsn)
	if err != nil {
		log.Fatal(err)
	}

	if err := m.Up(); err != nil && err.Error() != "no change" {
		log.Fatal(err)
	}
	logus.WriteLog(logus.LogLevelInfo, "Migration Success")
}
