package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxiesDefaultToNone(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if got := FromEnv().HTTP.TrustedProxies; len(got) != 0 {
		t.Fatalf("TrustedProxies = %v, want none", got)
	}
}

func TestTrustedProxiesAreReadAsAList(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1, 192.168.0.0/16 ,::1")
	want := []string{"10.0.0.1", "192.168.0.0/16", "::1"}
	if got := FromEnv().HTTP.TrustedProxies; !reflect.DeepEqual(got, want) {
		t.Fatalf("TrustedProxies = %v, want %v", got, want)
	}
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("Validate = %v", err)
	}
}

func TestInvalidTrustedProxyNamesTheVariableNotTheValue(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1,not-an-ip-secret")
	err := validateFromEnv(t)
	wantInError(t, err, "TRUSTED_PROXIES")
	if strings.Contains(err.Error(), "not-an-ip-secret") {
		t.Fatalf("the error leaks the value: %v", err)
	}
}

func TestShutdownDelayDefaultsToFiveSecondsAndStaysBelowTheTimeout(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if got := FromEnv().HTTP.ShutdownDelay; got != 5*time.Second {
		t.Fatalf("ShutdownDelay = %v, want 5s", got)
	}
	for _, c := range []struct{ delay, timeout string }{{"15s", "15s"}, {"20s", "15s"}, {"-1s", "15s"}} {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("HTTP_SHUTDOWN_DELAY", c.delay)
		t.Setenv("HTTP_SHUTDOWN_TIMEOUT", c.timeout)
		wantInError(t, validateFromEnv(t), "HTTP_SHUTDOWN_DELAY")
	}
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("HTTP_SHUTDOWN_DELAY", "0")
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("a zero delay is allowed: %v", err)
	}
}
