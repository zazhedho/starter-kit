package config

import (
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/gokit"
)

// Validate returns one error joining every problem with "; ". Problems name
// their variable and never include a value.
func (c Config) Validate() error {
	var problems []string
	// Read after FromEnv has finished reading everything, authkit included.
	if err := gokit.EnvErrors(); err != nil {
		problems = append(problems, strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	problems = append(problems, c.validatePort()...)
	problems = append(problems, c.validateApp()...)
	problems = append(problems, c.validateHTTP()...)
	problems = append(problems, c.validateDatabase()...)
	problems = append(problems, c.validateRedis()...)
	problems = append(problems, c.validateSMTP()...)
	problems = append(problems, c.validateLocation()...)
	problems = append(problems, c.validateMedia()...)

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func (c Config) validatePort() []string {
	port := strings.TrimSpace(c.App.Port)
	if port == "" {
		return []string{"PORT is required"}
	}
	if !validPort(port) {
		return []string{"PORT must be a number between 1 and 65535"}
	}
	return nil
}

func (c Config) validateApp() []string {
	// PostgreSQL does not know "Local", and an empty name would silently mean UTC.
	tz := strings.TrimSpace(c.App.Timezone)
	if tz == "" || tz == "Local" {
		return []string{"APP_TIMEZONE must be an IANA time zone name such as Asia/Jakarta"}
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return []string{"APP_TIMEZONE is not a known time zone"}
	}
	return nil
}

func (c Config) validateHTTP() []string {
	var problems []string
	for _, t := range []struct {
		key   string
		value time.Duration
	}{
		{"HTTP_READ_HEADER_TIMEOUT", c.HTTP.ReadHeaderTimeout},
		{"HTTP_READ_TIMEOUT", c.HTTP.ReadTimeout},
		{"HTTP_WRITE_TIMEOUT", c.HTTP.WriteTimeout},
		{"HTTP_IDLE_TIMEOUT", c.HTTP.IdleTimeout},
		{"HTTP_SHUTDOWN_TIMEOUT", c.HTTP.ShutdownTimeout},
	} {
		if t.value <= 0 {
			problems = append(problems, t.key+" must be greater than zero")
		}
	}
	if c.HTTP.MaxBodyBytes <= 0 {
		problems = append(problems, "HTTP_MAX_BODY_MB must be between 1 and 1024")
	}
	return problems
}

func (c Config) validateDatabase() []string {
	d := c.Database
	var problems []string

	if d.URL == "" {
		for _, f := range []struct{ key, value string }{
			{"DB_HOST", d.Host}, {"DB_PORT", d.Port}, {"DB_USERNAME", d.Username}, {"DB_NAME", d.Name},
		} {
			if f.value == "" {
				problems = append(problems, f.key+" is required when DATABASE_URL is empty")
			}
		}
		if d.Port != "" && !validPort(d.Port) {
			problems = append(problems, "DB_PORT must be a number between 1 and 65535")
		}
	}

	switch d.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		problems = append(problems, "DB_SSLMODE must be one of: disable, allow, prefer, require, verify-ca, verify-full")
	}

	if d.MaxOpenConns <= 0 {
		problems = append(problems, "DB_MAX_OPEN_CONNS must be greater than zero")
	}
	if d.MaxIdleConns < 0 {
		problems = append(problems, "DB_MAX_IDLE_CONNS must not be negative")
	}
	if d.ConnMaxLifetime <= 0 {
		problems = append(problems, "DB_CONN_MAX_LIFETIME must be greater than zero")
	}
	if d.ConnMaxIdleTime <= 0 {
		problems = append(problems, "DB_CONN_MAX_IDLE_TIME must be greater than zero")
	}
	return problems
}

func (c Config) validateRedis() []string {
	r := c.Redis
	if !r.Configured() {
		return nil
	}

	var problems []string
	if r.URL != "" {
		if _, err := redis.ParseURL(r.URL); err != nil {
			problems = append(problems, "REDIS_URL is invalid")
		}
	}
	if r.Port != "" && !validPort(r.Port) {
		problems = append(problems, "REDIS_PORT must be a number between 1 and 65535")
	}
	if r.DB < 0 {
		problems = append(problems, "REDIS_DB must be a non-negative integer")
	}
	return problems
}

func (c Config) validateSMTP() []string {
	s := c.SMTP
	if s.Host == "" && s.Password == "" && s.From == "" {
		return nil
	}

	var problems []string
	for _, f := range []struct {
		key string
		set bool
	}{
		{"SMTP_HOST", s.Host != ""}, {"SMTP_PASS", s.Password != ""}, {"SMTP_FROM", s.From != ""},
	} {
		if !f.set {
			problems = append(problems, f.key+" is required when SMTP is configured")
		}
	}
	if s.Port < 0 || s.Port > 65535 {
		problems = append(problems, "SMTP_PORT must be a number between 1 and 65535")
	}
	if s.From != "" {
		if _, err := mail.ParseAddress(s.From); err != nil {
			problems = append(problems, "SMTP_FROM must be a valid email address")
		}
	}
	return problems
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}
