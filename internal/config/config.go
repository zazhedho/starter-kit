// Package config holds the typed application configuration. FromEnv builds it
// from the process environment once, Validate checks it once, and the rest of
// the service receives the result instead of reading the environment itself.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zazhedho/authkit"
)

// Config is the whole application configuration.
type Config struct {
	App      App
	HTTP     HTTP
	Database Database
	Redis    Redis
	Migrate  Migrate
	Location Location
	Media    Media
	Storage  Storage
	Auth     authkit.Config // from authkit.ConfigFromEnv(); DB, Redis and Mailer are filled in later by the app

	// SMTPConfigured is true when SMTP_HOST, SMTP_PASS and SMTP_FROM are all set.
	SMTPConfigured bool

	smtp smtpSettings

	// problems holds environment values FromEnv could not parse; Validate
	// reports them. Each one names the variable, never its value.
	problems []string
}

// smtpSettings keeps what Validate needs to tell a partly configured SMTP
// setup apart from an unset one, without storing the password.
type smtpSettings struct {
	hostSet, passSet bool
	port, from       string
}

type App struct{ Name, Env, Port, Timezone string }

type HTTP struct {
	ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout, ShutdownTimeout time.Duration
	MaxBodyBytes                                                               int64
}

type Database struct {
	URL, Host, Port, Username, Password, Name, SSLMode string
	MaxOpenConns, MaxIdleConns                         int
	ConnMaxLifetime, ConnMaxIdleTime                   time.Duration
}

// DSN returns DATABASE_URL when set, otherwise a key=value DSN for gorm/pgx.
func (d Database) DSN(timezone string) string {
	if d.URL != "" {
		return d.URL
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		d.Host, d.Port, d.Username, d.Password, d.Name, d.SSLMode, timezone)
}

// String redacts the URL and the password.
func (d Database) String() string {
	return fmt.Sprintf("Database{URL:%s Host:%q Port:%q Username:%q Password:%s Name:%q SSLMode:%q MaxOpenConns:%d MaxIdleConns:%d ConnMaxLifetime:%s ConnMaxIdleTime:%s}",
		redact(d.URL), d.Host, d.Port, d.Username, redact(d.Password), d.Name, d.SSLMode,
		d.MaxOpenConns, d.MaxIdleConns, d.ConnMaxLifetime, d.ConnMaxIdleTime)
}

type Redis struct {
	URL, Host, Port, Password string
	DB                        int

	dbInvalid bool // REDIS_DB was set but is not an integer
}

// Configured reports whether a Redis connection should be attempted.
func (r Redis) Configured() bool { return r.URL != "" || r.Host != "" }

// String redacts the URL and the password.
func (r Redis) String() string {
	return fmt.Sprintf("Redis{URL:%s Host:%q Port:%q Password:%s DB:%d}",
		redact(r.URL), r.Host, r.Port, redact(r.Password), r.DB)
}

type Migrate struct {
	Run, Only bool
	Path      string
}

type Location struct {
	ServiceBaseURL, SourceYear string
	ServiceTimeout, CacheTTL   time.Duration
}

type Media struct {
	Enabled             bool
	MaxFileSizeBytes    int64
	AllowedContentTypes []string
	UploadRateLimit     int
	UploadRateWindow    time.Duration
	UploadTimeout       time.Duration
}

type Storage struct {
	Provider, Endpoint, AccessKey, SecretKey, Bucket, BaseURL, Region, R2AccountID string
	UseSSL                                                                         bool
}

// String redacts both keys.
func (s Storage) String() string {
	return fmt.Sprintf("Storage{Provider:%q Endpoint:%q AccessKey:%s SecretKey:%s Bucket:%q BaseURL:%q Region:%q R2AccountID:%q UseSSL:%t}",
		s.Provider, s.Endpoint, redact(s.AccessKey), redact(s.SecretKey), s.Bucket, withoutUserinfo(s.BaseURL), s.Region, s.R2AccountID, s.UseSSL)
}

// String is safe to log: secrets are reported only as set or unset, and Auth
// goes through its own redacting String.
func (c Config) String() string {
	return fmt.Sprintf("Config{App:%+v HTTP:%+v Database:%s Redis:%s Migrate:%+v Location:%+v Media:%+v Storage:%s Auth:%s SMTPConfigured:%t}",
		c.App, c.HTTP, c.Database, c.Redis, c.Migrate, c.Location, c.Media, c.Storage, c.Auth, c.SMTPConfigured)
}

// GoString keeps %#v from printing the raw fields.
func (c Config) GoString() string   { return c.String() }
func (d Database) GoString() string { return d.String() }
func (r Redis) GoString() string    { return r.String() }
func (s Storage) GoString() string  { return s.String() }

// withoutUserinfo drops any user:password part of a URL so it can be printed.
func withoutUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid"
	}
	u.User = nil
	return u.String()
}

func redact(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unset"
	}
	return "set"
}
