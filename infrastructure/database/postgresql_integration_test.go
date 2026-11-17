package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"starter-kit/internal/config"
)

const integrationTimezone = "Asia/Jakarta"

// adminSettings returns connection settings for the PostgreSQL named by
// STARTER_KIT_TEST_DATABASE_URL, in both shapes the service accepts: the
// DATABASE_URL form and the DB_* parts. The test is skipped when the variable
// is not set.
func adminSettings(t *testing.T) (viaURL, viaParts config.Database) {
	t.Helper()
	raw := os.Getenv("STARTER_KIT_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("STARTER_KIT_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("STARTER_KIT_TEST_DATABASE_URL is not a valid URL")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Hostname(), "5432"
	}
	password, _ := u.User.Password()
	sslmode := u.Query().Get("sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}
	pool := func(d config.Database) config.Database {
		d.MaxOpenConns, d.MaxIdleConns = 2, 1
		return d
	}
	viaURL = pool(config.Database{URL: raw})
	viaParts = pool(config.Database{
		Host: host, Port: port, Username: u.User.Username(), Password: password,
		Name: strings.TrimPrefix(u.Path, "/"), SSLMode: sslmode,
	})
	return viaURL, viaParts
}

func showTimeZone(t *testing.T, cfg config.Database) string {
	t.Helper()
	db, sqlDB, err := Open(cfg, integrationTimezone)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	var zone string
	if err := db.Raw("SHOW TimeZone").Scan(&zone).Error; err != nil {
		t.Fatalf("SHOW TimeZone: %v", err)
	}
	return zone
}

func TestIntegrationConnectsThroughBothPaths(t *testing.T) {
	viaURL, viaParts := adminSettings(t)
	for name, cfg := range map[string]config.Database{"DATABASE_URL": viaURL, "DB_* parts": viaParts} {
		t.Run(name, func(t *testing.T) {
			if got := showTimeZone(t, cfg); got != integrationTimezone {
				t.Fatalf("SHOW TimeZone = %q, want %q", got, integrationTimezone)
			}
		})
	}
}

// TestIntegrationDatabaseURLKeepsItsOwnTimeZone: a time zone written in the
// URL itself is not overridden.
func TestIntegrationDatabaseURLKeepsItsOwnTimeZone(t *testing.T) {
	viaURL, _ := adminSettings(t)
	u, _ := url.Parse(viaURL.URL)
	q := u.Query()
	q.Set("timezone", "UTC")
	u.RawQuery = q.Encode()
	cfg := viaURL
	cfg.URL = u.String()
	if got := showTimeZone(t, cfg); got != "UTC" {
		t.Fatalf("SHOW TimeZone = %q, want the zone from the URL (UTC)", got)
	}
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func TestIntegrationPasswordsWithSpecialCharacters(t *testing.T) {
	_, admin := adminSettings(t)
	adminDB, adminSQL, err := Open(admin, integrationTimezone)
	if err != nil {
		t.Fatalf("Open admin: %v", err)
	}
	t.Cleanup(func() { _ = adminSQL.Close() })

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	role := "sk_test_" + hex.EncodeToString(suffix)
	//nolint:gosec // G101: fixture value, not a real credential
	const password = `p ass'w\ord@:/`
	ctx := context.Background()
	if err := adminDB.WithContext(ctx).Exec("CREATE ROLE " + role + " LOGIN PASSWORD " + quoteLiteral(password)).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() { _ = adminDB.Exec("DROP ROLE IF EXISTS " + role).Error })

	t.Run("correct password connects", func(t *testing.T) {
		cfg := admin
		cfg.Username, cfg.Password = role, password
		if got := showTimeZone(t, cfg); got != integrationTimezone {
			t.Fatalf("SHOW TimeZone = %q", got)
		}
	})

	t.Run("wrong password is an authentication failure and never printed", func(t *testing.T) {
		const wrong = `wr ong'p\ass@:/-SECRET`
		cfg := admin
		cfg.Username, cfg.Password = role, wrong
		stop := captureOutput(t)
		_, sqlDB, err := Open(cfg, integrationTimezone)
		output := stop()
		if err == nil {
			_ = sqlDB.Close()
			t.Fatal("a wrong password was accepted")
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("error = %q, want the authentication failed kind", err)
		}
		for what, text := range map[string]string{"error": err.Error(), "output": output} {
			for _, secret := range []string{wrong, password, "SECRET"} {
				if strings.Contains(text, secret) {
					t.Errorf("%s contains part of a password (%q): %q", what, secret, text)
				}
			}
		}
	})
}
