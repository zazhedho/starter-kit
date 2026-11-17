package database

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"starter-kit/internal/config"
)

// TestOpenErrorDoesNotLeakCredentials uses inputs that make the driver echo
// part of the DSN in its own error text (a refused connection never does).
func TestOpenErrorDoesNotLeakCredentials(t *testing.T) {
	parts := func(password string) config.Database {
		return config.Database{
			Host: "127.0.0.1", Port: "1", Username: "starter", Password: password,
			Name: "app", SSLMode: "disable", MaxOpenConns: 1, MaxIdleConns: 1,
		}
	}
	//nolint:gosec // G101: fixture values, not real credentials
	cases := map[string]config.Database{
		"space":     parts("p ass-SECRET"),
		"quote":     parts("p'ass-SECRET"),
		"backslash": parts(`p\ass-SECRET`),
		"at-colon":  parts("p@ss:/-SECRET"),
		"malformed url": {
			URL: "postgres://u:p%ZZ-SECRET@127.0.0.1:1/db", MaxOpenConns: 1,
		},
		"url refused": {
			URL: "postgres://u:p-SECRET@127.0.0.1:1/db?sslmode=disable", MaxOpenConns: 1,
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			mark := logs.Mark()
			_, sqlDB, err := Open(cfg, "Asia/Jakarta")
			output := logs.Since(mark)
			if output == "" {
				t.Fatal("no log output was captured, so the leak check below would prove nothing")
			}
			if err == nil {
				if sqlDB != nil {
					_ = sqlDB.Close()
				}
				t.Fatal("expected an error")
			}
			for what, text := range map[string]string{"error": err.Error(), "output": output} {
				if strings.Contains(text, "SECRET") {
					t.Errorf("%s leaks the password: %q", what, text)
				}
			}
		})
	}
}

func TestOpenInvalidURLReturnsParseError(t *testing.T) {
	cfg := config.Database{URL: "postgres://%", MaxOpenConns: 1}
	_, sqlDB, err := Open(cfg, "Asia/Jakarta")
	if err == nil {
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
		t.Fatal("expected invalid dsn error")
	}
}

func TestClassifyDistinguishesRejectionFromUnreachable(t *testing.T) {
	timeout := &net.DNSError{IsTimeout: true}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"wrong password", &pgconn.PgError{Code: "28P01"}, "authentication failed"},
		{"role not permitted", &pgconn.PgError{Code: "28000"}, "authentication failed"},
		{"bad parameter value", &pgconn.PgError{Code: "22023"}, "server rejected the connection parameters"},
		{"database missing", &pgconn.PgError{Code: "3D000"}, "server rejected the connection parameters"},
		{"wrapped rejection", fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: "22023"}), "server rejected the connection parameters"},
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), "connection refused"},
		{"timeout", timeout, "timed out"},
		{"no such host", &net.DNSError{Err: "no such host"}, "unreachable"},
		{"parse", &pgconn.ParseConfigError{}, "invalid configuration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.err); got != c.want {
				t.Fatalf("classify = %q, want %q", got, c.want)
			}
		})
	}
}
