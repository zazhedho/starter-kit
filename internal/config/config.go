// Package config holds the typed application configuration and is the only
// package that reads the environment. LoadDotEnv and LoadRemote fill the
// environment from .env and from Consul or a config file, FromEnv builds the
// typed Config from it once, Validate checks it once, and the rest of the
// service receives the result instead of reading the environment itself.
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

	SMTP SMTP

	// problems holds environment values FromEnv could not parse; Validate
	// reports them. Each one names the variable, never its value.
	problems []string

	smtpPortInvalid bool // SMTP_PORT was set but is not a port number
}

// SMTP is the outgoing mail setting for OTP and password-reset emails. Empty
// values mean "use the mailer's default"; only Host, Password and From are
// required, and only when mail is used at all.
type SMTP struct {
	Host         string // SMTP_HOST
	Port         int    // SMTP_PORT; 0 when unset
	User         string // SMTP_USER
	Password     string // SMTP_PASS
	From         string // SMTP_FROM
	OTPSubject   string // SMTP_SUBJECT
	ResetSubject string // RESET_SUBJECT
	AppName      string // AUTH_EMAIL_APP_NAME
}

// Configured is true when SMTP_HOST, SMTP_PASS and SMTP_FROM are all set.
func (s SMTP) Configured() bool { return s.Host != "" && s.Password != "" && s.From != "" }

// String redacts the password.
func (s SMTP) String() string {
	return fmt.Sprintf("SMTP{Host:%q Port:%d User:%q Password:%s From:%q OTPSubject:%q ResetSubject:%q AppName:%q}",
		s.Host, s.Port, s.User, redact(s.Password), s.From, s.OTPSubject, s.ResetSubject, s.AppName)
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

// DSN returns DATABASE_URL when set, otherwise a key=value DSN that pgx parses.
// Every value is single-quoted with \ and ' escaped, so a space, quote or
// backslash in a user name or password neither breaks the DSN nor splits it
// into pieces that an error message could echo.
func (d Database) DSN(timezone string) string {
	if d.URL != "" {
		return d.URL
	}
	var b strings.Builder
	for i, kv := range [][2]string{
		{"host", d.Host}, {"port", d.Port}, {"user", d.Username}, {"password", d.Password},
		{"dbname", d.Name}, {"sslmode", d.SSLMode}, {"TimeZone", timezone},
	} {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[0] + "='" + dsnEscaper.Replace(kv[1]) + "'")
	}
	return b.String()
}

var dsnEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

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
	return fmt.Sprintf("Config{App:%+v HTTP:%+v Database:%s Redis:%s Migrate:%+v Location:%+v Media:%+v Storage:%s SMTP:%s Auth:%s}",
		c.App, c.HTTP, c.Database, c.Redis, c.Migrate, c.Location, c.Media, c.Storage, c.SMTP, c.Auth)
}

// GoString keeps %#v from printing the raw fields.
func (c Config) GoString() string   { return c.String() }
func (d Database) GoString() string { return d.String() }
func (r Redis) GoString() string    { return r.String() }
func (s Storage) GoString() string  { return s.String() }
func (s SMTP) GoString() string     { return s.String() }

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
