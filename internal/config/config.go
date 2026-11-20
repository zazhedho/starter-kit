package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/zazhedho/authkit"
)

type Config struct {
	App      App
	HTTP     HTTP
	Database Database
	Redis    Redis
	Migrate  Migrate
	Location Location
	Media    Media
	Storage  Storage
	Auth     authkit.Config

	SMTP SMTP

	authErr error
}

type SMTP struct {
	Host         string
	Port         int
	User         string
	Password     string
	From         string
	OTPSubject   string
	ResetSubject string
	AppName      string
}

func (s SMTP) Configured() bool { return s.Host != "" && s.Password != "" && s.From != "" }

func (s SMTP) String() string {
	return fmt.Sprintf("SMTP{Host:%q Port:%d User:%q Password:%s From:%q OTPSubject:%q ResetSubject:%q AppName:%q}",
		s.Host, s.Port, s.User, redact(s.Password), s.From, s.OTPSubject, s.ResetSubject, s.AppName)
}

type App struct{ Name, Env, Port, Timezone string }

type HTTP struct {
	ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout, ShutdownTimeout time.Duration
	ShutdownDelay                                                              time.Duration
	MaxBodyBytes                                                               int64
	// Empty trusts none: X-Forwarded-For is ignored and the client IP is the remote address.
	TrustedProxies []string
}

type Database struct {
	URL, Host, Port, Username, Password, Name, SSLMode string
	MaxOpenConns, MaxIdleConns                         int
	ConnMaxLifetime, ConnMaxIdleTime                   time.Duration
}

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

func (d Database) String() string {
	return fmt.Sprintf("Database{URL:%s Host:%q Port:%q Username:%q Password:%s Name:%q SSLMode:%q MaxOpenConns:%d MaxIdleConns:%d ConnMaxLifetime:%s ConnMaxIdleTime:%s}",
		redact(d.URL), d.Host, d.Port, d.Username, redact(d.Password), d.Name, d.SSLMode,
		d.MaxOpenConns, d.MaxIdleConns, d.ConnMaxLifetime, d.ConnMaxIdleTime)
}

type Redis struct {
	URL, Host, Port, Password string
	DB                        int
}

func (r Redis) Configured() bool { return r.URL != "" || r.Host != "" }

func (r Redis) String() string {
	return fmt.Sprintf("Redis{URL:%s Host:%q Port:%q Password:%s DB:%d}",
		redact(r.URL), r.Host, r.Port, redact(r.Password), r.DB)
}

type Migrate struct {
	Run, Only bool
	Path      string
}

func (c Config) String() string {
	return fmt.Sprintf("Config{App:%+v HTTP:%+v Database:%s Redis:%s Migrate:%+v Location:%+v Media:%+v Storage:%s SMTP:%s Auth:%s}",
		c.App, c.HTTP, c.Database, c.Redis, c.Migrate, c.Location, c.Media, c.Storage, c.SMTP, c.Auth)
}

func (c Config) GoString() string   { return c.String() }
func (d Database) GoString() string { return d.String() }
func (r Redis) GoString() string    { return r.String() }
func (s SMTP) GoString() string     { return s.String() }

func redact(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unset"
	}
	return "set"
}
