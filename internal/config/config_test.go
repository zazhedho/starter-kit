package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zazhedho/gokit"
)

var managedEnv = []string{
	"APP_NAME", "APP_ENV", "PORT", "APP_TIMEZONE", "JWT_KEY", "OTP_SECRET", "RESET_SECRET",
	"HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT",
	"HTTP_SHUTDOWN_TIMEOUT", "HTTP_SHUTDOWN_DELAY", "HTTP_MAX_BODY_MB", "TRUSTED_PROXIES",
	"DATABASE_URL", "DB_HOST", "DB_PORT", "DB_USERNAME", "DB_PASS", "DB_NAME", "DB_SSLMODE",
	"DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS", "DB_CONN_MAX_LIFETIME", "DB_CONN_MAX_IDLE_TIME",
	"REDIS_URL", "REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB",
	"RUN_MIGRATION", "PATH_MIGRATE",
	"LOCATION_SERVICE_BASE_URL", "LOCATION_SERVICE_TIMEOUT_SECONDS", "LOCATION_CACHE_TTL",
	"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "SMTP_SUBJECT", "RESET_SUBJECT", "AUTH_EMAIL_APP_NAME",
	"MEDIA_ENABLED", "MEDIA_MAX_FILE_SIZE_MB", "MEDIA_ALLOWED_CONTENT_TYPES", "MEDIA_UPLOAD_RATE_LIMIT",
	"MEDIA_UPLOAD_RATE_WINDOW_SECONDS", "MEDIA_UPLOAD_TIMEOUT", "MEDIA_UPLOAD_MAX_CONCURRENT", "MEDIA_UPLOAD_MAX_CONCURRENT_PER_USER",
	"MEDIA_UPLOAD_USER_RATE_LIMIT", "MEDIA_UPLOAD_USER_RATE_WINDOW_SECONDS",
	"LOCATION_SERVICE_MAX_RESPONSE_MB", "LOCATION_RATE_LIMIT", "LOCATION_RATE_WINDOW_SECONDS", "STORAGE_PUBLIC_READ",
	"STORAGE_PROVIDER", "STORAGE_ENDPOINT", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY", "STORAGE_BUCKET_NAME",
	"STORAGE_BASE_URL", "STORAGE_REGION", "STORAGE_USE_SSL", "R2_ACCOUNT_ID",
	"JWT_EXP", "JWT_EXP_MINUTES", "SESSION_MAX_LIFETIME_HOURS", "AUTH_RATE_LIMIT", "AUTH_RATE_WINDOW_SECONDS",
	"LIMITER_FAIL_CLOSED", "LOGIN_WITH_PHONE",
}

func clearEnv(t *testing.T) {
	t.Helper()
	gokit.ResetEnvErrors()
	t.Cleanup(gokit.ResetEnvErrors)
	for _, key := range managedEnv {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PORT", "8080")
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_USERNAME", "starter")
	t.Setenv("DB_NAME", "starter")
}

func validateFromEnv(t *testing.T) error {
	t.Helper()
	return FromEnv().Validate()
}

func wantInError(t *testing.T, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected %q in error %q", want, err.Error())
		}
	}
}

func TestFromEnvDefaults(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	cfg := FromEnv()

	wantHTTP := HTTP{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   15 * time.Second,
		ShutdownDelay:     5 * time.Second,
		MaxBodyBytes:      10 << 20,
	}
	if !reflect.DeepEqual(cfg.HTTP, wantHTTP) {
		t.Fatalf("HTTP = %+v, want %+v", cfg.HTTP, wantHTTP)
	}
	assertDefaultAppAndDatabase(t, cfg)
	assertDefaultMedia(t, cfg.Media)
	assertDefaultIntegrations(t, cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults with required env must validate, got %v", err)
	}
}

func assertDefaultAppAndDatabase(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.App.Timezone != "Asia/Jakarta" {
		t.Fatalf("Timezone = %q", cfg.App.Timezone)
	}
	if cfg.App.Port != "8080" {
		t.Fatalf("Port = %q", cfg.App.Port)
	}
	db := cfg.Database
	if db.MaxOpenConns != 100 || db.MaxIdleConns != 10 || db.ConnMaxLifetime != time.Hour || db.ConnMaxIdleTime != 5*time.Minute {
		t.Fatalf("database pool = %+v", db)
	}
	if db.SSLMode != "disable" {
		t.Fatalf("SSLMode = %q", db.SSLMode)
	}
	if cfg.Migrate != (Migrate{Run: true, Path: "file://migrations"}) {
		t.Fatalf("Migrate = %+v", cfg.Migrate)
	}
}

func assertDefaultMedia(t *testing.T, m Media) {
	t.Helper()
	if m.UploadTimeout != time.Minute || m.MaxFileSizeBytes != 5<<20 || m.UploadRateLimit != 20 || m.UploadRateWindow != 60*time.Second {
		t.Fatalf("Media = %+v", m)
	}
	if m.Enabled {
		t.Fatal("media must be disabled by default")
	}
	if got := strings.Join(m.AllowedContentTypes, ","); got != "application/pdf,image/gif,image/jpeg,image/png,image/webp" {
		t.Fatalf("AllowedContentTypes = %q", got)
	}
}

func assertDefaultIntegrations(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.Location.ServiceTimeout != 20*time.Second || cfg.Location.CacheTTL != 180*24*time.Hour {
		t.Fatalf("Location = %+v", cfg.Location)
	}
	if cfg.Storage.Provider != "minio" || cfg.Storage.Region != "" || cfg.Storage.UseSSL {
		t.Fatalf("Storage = %+v", cfg.Storage)
	}
	if cfg.Redis.Configured() {
		t.Fatal("redis must not be configured by default")
	}
	if cfg.Redis.Port != "6379" || cfg.Redis.DB != 0 {
		t.Fatalf("Redis = %+v", cfg.Redis)
	}
	if cfg.SMTP.Configured() {
		t.Fatal("SMTP must not be configured by default")
	}
}

func TestFromEnvReadsOverrides(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	for k, v := range map[string]string{
		"APP_NAME": "svc", "APP_ENV": "production", "APP_TIMEZONE": "UTC",
		"HTTP_READ_HEADER_TIMEOUT": "1s", "HTTP_READ_TIMEOUT": "2s", "HTTP_WRITE_TIMEOUT": "3s",
		"HTTP_IDLE_TIMEOUT": "4s", "HTTP_SHUTDOWN_TIMEOUT": "5s", "HTTP_SHUTDOWN_DELAY": "1s", "HTTP_MAX_BODY_MB": "20",
		"MEDIA_UPLOAD_TIMEOUT": "3m",
		"DB_MAX_OPEN_CONNS":    "50", "DB_MAX_IDLE_CONNS": "5", "DB_CONN_MAX_LIFETIME": "30m", "DB_CONN_MAX_IDLE_TIME": "2m",
		"RUN_MIGRATION": "false", "REDIS_HOST": "cache",
		"LOCATION_SERVICE_TIMEOUT_SECONDS": "7", "MEDIA_UPLOAD_RATE_WINDOW_SECONDS": "90",
		"LOCATION_CACHE_TTL": "24h",
		"SMTP_HOST":          "smtp.example.com", "SMTP_PASS": "x", "SMTP_FROM": "a@example.com",
	} {
		t.Setenv(k, v)
	}
	cfg := FromEnv()

	if cfg.App.Name != "svc" || cfg.App.Env != "production" || cfg.App.Timezone != "UTC" {
		t.Fatalf("App = %+v", cfg.App)
	}
	want := HTTP{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second, time.Second, 20 << 20, nil}
	if !reflect.DeepEqual(cfg.HTTP, want) {
		t.Fatalf("HTTP = %+v, want %+v", cfg.HTTP, want)
	}
	if cfg.Media.UploadTimeout != 3*time.Minute || cfg.Media.UploadRateWindow != 90*time.Second {
		t.Fatalf("Media = %+v", cfg.Media)
	}
	db := cfg.Database
	if db.MaxOpenConns != 50 || db.MaxIdleConns != 5 || db.ConnMaxLifetime != 30*time.Minute || db.ConnMaxIdleTime != 2*time.Minute {
		t.Fatalf("database pool = %+v", db)
	}
	if cfg.Migrate.Run {
		t.Fatal("RUN_MIGRATION=false must disable migration")
	}
	if cfg.Redis.Host != "cache" || !cfg.Redis.Configured() {
		t.Fatalf("Redis = %+v", cfg.Redis)
	}
	if cfg.Location.ServiceTimeout != 7*time.Second || cfg.Location.CacheTTL != 24*time.Hour {
		t.Fatalf("Location = %+v", cfg.Location)
	}
	if !cfg.SMTP.Configured() {
		t.Fatal("SMTP must be configured when host, pass and from are set")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestFromEnvReadsSMTP(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	//nolint:gosec // G101: fixture values, not real credentials
	for k, v := range map[string]string{
		"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "2525", "SMTP_USER": "mailer",
		"SMTP_PASS": "smtp-PASS-SECRET", "SMTP_FROM": "Team <a@example.com>",
		"SMTP_SUBJECT": "Your code", "RESET_SUBJECT": "Reset it", "AUTH_EMAIL_APP_NAME": "Starter",
	} {
		t.Setenv(k, v)
	}
	cfg := FromEnv()
	//nolint:gosec // G101: fixture values, not real credentials
	want := SMTP{
		Host: "smtp.example.com", Port: 2525, User: "mailer", Password: "smtp-PASS-SECRET",
		From: "Team <a@example.com>", OTPSubject: "Your code", ResetSubject: "Reset it", AppName: "Starter",
	}
	if cfg.SMTP != want {
		t.Fatalf("SMTP = %+v, want %+v", cfg.SMTP, want)
	}
	if !cfg.SMTP.Configured() {
		t.Fatal("SMTP must be configured")
	}
	out := fmt.Sprintf("%v %+v %#v %s %v %+v %#v", cfg, cfg, cfg, cfg, cfg.SMTP, cfg.SMTP, cfg.SMTP)
	if strings.Contains(out, "smtp-PASS-SECRET") {
		t.Fatalf("output leaks the SMTP password: %s", out)
	}
	if !strings.Contains(out, "smtp.example.com") {
		t.Fatalf("output lacks the SMTP host: %s", out)
	}
}

func TestSMTPDefaultsAreEmptySoTheSenderAppliesItsOwn(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if got := FromEnv().SMTP; got != (SMTP{}) {
		t.Fatalf("SMTP = %+v, want the zero value when nothing is set", got)
	}
}

func TestSMTPConfiguredNeedsHostPassAndFrom(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "a@example.com")
	if FromEnv().SMTP.Configured() {
		t.Fatal("host and from without pass must not count as configured")
	}
}

func TestRedisConfiguredOnlyByURLOrHost(t *testing.T) {
	clearEnv(t)
	t.Setenv("REDIS_PORT", "6379")
	t.Setenv("REDIS_DB", "0")
	if FromEnv().Redis.Configured() {
		t.Fatal("REDIS_PORT and REDIS_DB alone must not configure redis")
	}

	clearEnv(t)
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	if !FromEnv().Redis.Configured() {
		t.Fatal("REDIS_URL alone must configure redis")
	}

	clearEnv(t)
	t.Setenv("REDIS_HOST", "cache")
	if !FromEnv().Redis.Configured() {
		t.Fatal("REDIS_HOST alone must configure redis")
	}
}

func TestValidate(t *testing.T) {
	t.Run("accepts required only", validateAcceptsRequiredOnly)

	t.Run("rejects an unknown DB_SSLMODE", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("DB_SSLMODE", "required")
		wantInError(t, validateFromEnv(t), "DB_SSLMODE")
	})

	t.Run("accepts every PostgreSQL sslmode", validateAcceptsEverySSLMode)

	t.Run("rejects Local as APP_TIMEZONE", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("APP_TIMEZONE", "Local")
		wantInError(t, validateFromEnv(t), "APP_TIMEZONE")
	})

	t.Run("rejects blank and Local APP_TIMEZONE on a built config", validateRejectsBlankTimezone)

	t.Run("allows database url without parts", validateAllowsDatabaseURLWithoutParts)

	t.Run("requires core config", validateRequiresCoreConfig)

	t.Run("rejects bad ports", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("PORT", "99999")
		t.Setenv("DB_HOST", "localhost")
		t.Setenv("DB_PORT", "abc")
		t.Setenv("DB_USERNAME", "u")
		t.Setenv("DB_NAME", "n")
		wantInError(t, validateFromEnv(t),
			"PORT must be a number between 1 and 65535",
			"DB_PORT must be a number between 1 and 65535",
		)
	})

	t.Run("validates configured smtp only", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "bad-port")
		t.Setenv("SMTP_FROM", "not-an-email")
		wantInError(t, validateFromEnv(t),
			"SMTP_PASS is required when SMTP is configured",
			"SMTP_PORT must be a valid int",
			"SMTP_FROM must be a valid email address",
		)
	})

	t.Run("ignores optional labels without connection config", validateIgnoresOptionalLabels)

	t.Run("validates configured redis and storage only", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("REDIS_HOST", "cache")
		t.Setenv("REDIS_PORT", "70000")
		t.Setenv("REDIS_DB", "-1")
		t.Setenv("STORAGE_PROVIDER", "local")
		t.Setenv("STORAGE_ENDPOINT", "localhost:9000")
		wantInError(t, validateFromEnv(t),
			"REDIS_PORT must be a number between 1 and 65535",
			"REDIS_DB must be a non-negative integer",
			"STORAGE_PROVIDER must be one of: minio, r2, cloudflare, cloudflare-r2",
			"STORAGE_ACCESS_KEY is required when storage is configured",
		)
	})

	t.Run("reports unparsable and invalid redis settings", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("REDIS_URL", "://bad")
		t.Setenv("REDIS_DB", "abc")
		wantInError(t, validateFromEnv(t),
			"REDIS_URL is invalid",
			"REDIS_DB must be a valid int",
		)
	})

	t.Run("http timeouts must be positive", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("HTTP_READ_HEADER_TIMEOUT", "0s")
		t.Setenv("HTTP_READ_TIMEOUT", "-1s")
		t.Setenv("HTTP_WRITE_TIMEOUT", "0s")
		t.Setenv("HTTP_IDLE_TIMEOUT", "0s")
		t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "0s")
		wantInError(t, validateFromEnv(t),
			"HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "HTTP_SHUTDOWN_TIMEOUT",
		)
	})

	t.Run("unparsable new durations and ints are reported and fall back", validateReportsUnparsableAndFallsBack)

	t.Run("a blank variable uses the default", validateBlankVariableUsesDefault)

	t.Run("durations accept bare seconds and Go syntax", validateDurationSyntax)

	t.Run("every invalid variable is reported, named, and never echoed", validateNeverEchoesValues)

	t.Run("database pool limits", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("DB_MAX_OPEN_CONNS", "0")
		t.Setenv("DB_MAX_IDLE_CONNS", "-1")
		t.Setenv("DB_CONN_MAX_IDLE_TIME", "0s")
		wantInError(t, validateFromEnv(t), "DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS", "DB_CONN_MAX_IDLE_TIME")
	})
}

func validateAcceptsRequiredOnly(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("expected valid startup config, got %v", err)
	}
}

func validateAcceptsEverySSLMode(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"} {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("DB_SSLMODE", mode)
		if err := validateFromEnv(t); err != nil {
			t.Fatalf("DB_SSLMODE=%s rejected: %v", mode, err)
		}
	}
}

func validateRejectsBlankTimezone(t *testing.T) {
	for _, tz := range []string{"", " ", "  Local  "} {
		clearEnv(t)
		setRequiredEnv(t)
		cfg := FromEnv()
		cfg.App.Timezone = tz
		wantInError(t, cfg.Validate(), "APP_TIMEZONE")
	}
}

func validateAllowsDatabaseURLWithoutParts(t *testing.T) {
	clearEnv(t)
	t.Setenv("PORT", "8080")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/app?sslmode=disable")
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("expected DATABASE_URL to satisfy db config, got %v", err)
	}
}

func validateRequiresCoreConfig(t *testing.T) {
	clearEnv(t)
	err := validateFromEnv(t)
	wantInError(t, err,
		"PORT is required",
		"DB_HOST is required when DATABASE_URL is empty",
		"DB_PORT is required when DATABASE_URL is empty",
		"DB_USERNAME is required when DATABASE_URL is empty",
		"DB_NAME is required when DATABASE_URL is empty",
	)
	if strings.Contains(strings.ToLower(err.Error()), "jwt") {
		t.Fatalf("JWT key is validated by authkit.New, not startup config: %q", err.Error())
	}
}

func validateIgnoresOptionalLabels(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USER", "apikey")
	t.Setenv("SMTP_SUBJECT", "Your OTP")
	t.Setenv("RESET_SUBJECT", "Reset Password")
	t.Setenv("STORAGE_PROVIDER", "local")
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("expected optional labels without connection config to be ignored, got %v", err)
	}
}

func validateReportsUnparsableAndFallsBack(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("HTTP_READ_TIMEOUT", "soon")
	t.Setenv("MEDIA_UPLOAD_TIMEOUT", "later")
	t.Setenv("DB_CONN_MAX_LIFETIME", "forever")
	t.Setenv("DB_MAX_OPEN_CONNS", "many")
	t.Setenv("HTTP_MAX_BODY_MB", "big")
	cfg := FromEnv()
	if cfg.HTTP.ReadTimeout != 30*time.Second || cfg.Media.UploadTimeout != time.Minute || cfg.Database.MaxOpenConns != 100 {
		t.Fatalf("unparsable values must fall back to defaults: %+v %+v %+v", cfg.HTTP, cfg.Media, cfg.Database)
	}
	wantInError(t, cfg.Validate(),
		"HTTP_READ_TIMEOUT", "MEDIA_UPLOAD_TIMEOUT", "DB_CONN_MAX_LIFETIME", "DB_MAX_OPEN_CONNS", "HTTP_MAX_BODY_MB",
	)
}

func validateBlankVariableUsesDefault(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("DB_SSLMODE", "")
	t.Setenv("HTTP_READ_TIMEOUT", "  ")
	cfg := FromEnv()
	if cfg.Database.SSLMode != "disable" || cfg.HTTP.ReadTimeout != 30*time.Second {
		t.Fatalf("blank values must use defaults: %q %v", cfg.Database.SSLMode, cfg.HTTP.ReadTimeout)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("blank values must not be errors, got %v", err)
	}
}

func validateDurationSyntax(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("HTTP_READ_TIMEOUT", "60")
	t.Setenv("HTTP_WRITE_TIMEOUT", "30s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "1m")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "1h")
	cfg := FromEnv()
	if cfg.HTTP.ReadTimeout != 60*time.Second || cfg.HTTP.WriteTimeout != 30*time.Second ||
		cfg.HTTP.IdleTimeout != time.Minute || cfg.HTTP.ShutdownTimeout != time.Hour {
		t.Fatalf("durations not parsed: %+v", cfg.HTTP)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func validateNeverEchoesValues(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("HTTP_READ_TIMEOUT", "3os-SECRET")
	t.Setenv("REDIS_DB", "x-SECRET")
	err := validateFromEnv(t)
	wantInError(t, err, "HTTP_READ_TIMEOUT must be a valid", "REDIS_DB must be a valid")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error echoes a value: %q", err.Error())
	}
}

func TestValidateErrorsNeverContainSecrets(t *testing.T) {
	clearEnv(t)
	secrets := []string{"p@ss-SECRET", "redis-SECRET", "storage-SECRET", "access-SECRET"}
	cfg := FromEnv()
	cfg.App.Port = "bad"
	cfg.Database = Database{Host: "h", Port: "bad", Password: secrets[0], URL: ""}
	cfg.Redis = Redis{Host: "cache", Port: "bad", Password: secrets[1], DB: -1}
	cfg.Storage = Storage{Provider: "weird", Endpoint: "e", SecretKey: secrets[2], AccessKey: secrets[3], BaseURL: "not a url"}
	cfg.Media.Enabled = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks secret %q: %q", secret, err.Error())
		}
	}
}

func TestStringRedactsSecrets(t *testing.T) {
	clearEnv(t)
	t.Setenv("JWT_KEY", "jwt-SECRET-0123456789-0123456789-0123")
	cfg := FromEnv()
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Database = Database{
		URL: "postgres://u:db-URL-SECRET@h/db", Host: "h", Password: "db-PASS-SECRET",
	}
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Redis = Redis{URL: "redis://:redis-URL-SECRET@h", Password: "redis-PASS-SECRET"}
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Storage = Storage{AccessKey: "storage-ACCESS-SECRET", SecretKey: "storage-KEY-SECRET"}

	out := fmt.Sprintf("%v %+v %s %v %+v %v", cfg, cfg, cfg, cfg.Database, cfg.Redis, cfg.Storage)
	for _, secret := range []string{
		"db-URL-SECRET", "db-PASS-SECRET", "redis-URL-SECRET", "redis-PASS-SECRET",
		"storage-ACCESS-SECRET", "storage-KEY-SECRET", "jwt-SECRET",
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("String output leaks %q: %s", secret, out)
		}
	}
}

func TestDatabaseDSN(t *testing.T) {
	//nolint:gosec // G101: fixture value, not a real credential
	withURL := Database{URL: "postgres://u:p@h:5432/db?sslmode=disable", Host: "ignored"}
	if got := withURL.DSN("Asia/Jakarta"); got != withURL.URL {
		t.Fatalf("DSN = %q, want the URL", got)
	}

	parts := Database{Host: "localhost", Port: "5432", Username: "starter", Password: "pw", Name: "app", SSLMode: "disable"}
	dsn := parts.DSN("Asia/Jakarta")
	for _, want := range []string{"host='localhost'", "port='5432'", "user='starter'", "dbname='app'", "sslmode='disable'", "TimeZone='Asia/Jakarta'"} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("expected %q in DSN %q", want, dsn)
		}
	}
}

func TestDatabaseDSNRoundTripsAwkwardValues(t *testing.T) {
	for _, password := range []string{"plain", "p ass", "p'ass", `p\ass`, "p@ss:word/x?y=z#w", `a b'c\d`} {
		d := Database{Host: "db.internal", Port: "5433", Username: "us er", Password: password, Name: "my db", SSLMode: "disable"}
		cfg, err := pgconn.ParseConfig(d.DSN("Asia/Jakarta"))
		if err != nil {
			t.Fatalf("password %q: DSN does not parse: %v", password, err)
		}
		if cfg.Password != password || cfg.User != "us er" || cfg.Host != "db.internal" ||
			cfg.Port != 5433 || cfg.Database != "my db" || cfg.RuntimeParams["TimeZone"] != "Asia/Jakarta" {
			t.Errorf("password %q: parsed back as %+v", password, cfg)
		}
	}
}

func TestValidateReportsAuthkitEnvironmentErrors(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("AUTH_RATE_LIMIT", "lots")
	t.Setenv("LOGIN_WITH_PHONE", "maybe")

	err := validateFromEnv(t)
	wantInError(t, err, "AUTH_RATE_LIMIT must be a valid integer", "LOGIN_WITH_PHONE must be a valid boolean")
	if strings.Contains(err.Error(), "lots") || strings.Contains(err.Error(), "maybe") {
		t.Fatalf("error echoes a value: %v", err)
	}
}

func TestFromEnvReadsTheNewAuthkitVariables(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("JWT_EXP_MINUTES", "20")
	t.Setenv("SESSION_MAX_LIFETIME_HOURS", "48")
	t.Setenv("AUTH_RATE_LIMIT", "7")
	t.Setenv("AUTH_RATE_WINDOW_SECONDS", "90")
	t.Setenv("LIMITER_FAIL_CLOSED", "true")
	t.Setenv("LOGIN_WITH_PHONE", "true")

	cfg := FromEnv()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	a := cfg.Auth
	if a.AccessTokenTTL != 20*time.Minute || a.SessionMaxLifetime != 48*time.Hour ||
		a.AuthRate.Limit != 7 || a.AuthRate.Window != 90*time.Second || !a.FailClosedLimiters || !a.PhoneLogin {
		t.Fatalf("authkit config not read from the environment: %+v", a)
	}
}

func TestNormalizeKey(t *testing.T) {
	if got := normalizeKey("  R2 "); got != "r2" {
		t.Fatalf("normalizeKey = %q", got)
	}
	if got := normalizeUpperKey(" db_host\t"); got != "DB_HOST" {
		t.Fatalf("normalizeUpperKey = %q", got)
	}
}
