package database

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"testing"

	"starter-kit/internal/config"
)

// captureOutput collects everything written to the process stdout and stderr
// file descriptors (where loggers write) and to the standard log package.
// It returns a function that stops capturing and returns what was written.
func captureOutput(t *testing.T) (stop func() string) {
	t.Helper()
	var buf, logBuf bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logBuf)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut, err := syscall.Dup(1)
	if err != nil {
		t.Fatal(err)
	}
	savedErr, err := syscall.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Dup2(int(w.Fd()), 1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Dup2(int(w.Fd()), 2); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	stopped := false
	stop = func() string {
		if stopped {
			return ""
		}
		stopped = true
		_ = syscall.Dup2(savedOut, 1)
		_ = syscall.Dup2(savedErr, 2)
		_ = syscall.Close(savedOut)
		_ = syscall.Close(savedErr)
		_ = w.Close()
		<-done
		_ = r.Close()
		log.SetOutput(oldLog)
		return buf.String() + logBuf.String()
	}
	t.Cleanup(func() { stop() })
	return stop
}

func TestOpenErrorDoesNotLeakDSN(t *testing.T) {
	stop := captureOutput(t)
	cfg := config.Database{
		Host: "127.0.0.1", Port: "1", Username: "starter", Password: "p@ss-SECRET",
		Name: "app", SSLMode: "disable", MaxOpenConns: 1, MaxIdleConns: 1,
	}
	db, sqlDB, err := Open(cfg, "Asia/Jakarta")
	output := stop()
	if err == nil {
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
		t.Fatalf("expected connection error, db=%v", db)
	}
	dsn := cfg.DSN("Asia/Jakarta")
	for name, text := range map[string]string{"error": err.Error(), "output": output} {
		if strings.Contains(text, "p@ss-SECRET") || strings.Contains(text, dsn) {
			t.Fatalf("%s leaks the password or DSN: %q", name, text)
		}
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
