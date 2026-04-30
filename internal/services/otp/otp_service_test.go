package serviceotp

import (
	"context"
	"errors"
	"starter-kit/pkg/config"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type otpRepoTestDouble struct {
	otp             map[string]string
	attempts        map[string]int
	cooldownTTL     time.Duration
	sendCount       int
	sendRetryAfter  time.Duration
	deletedEmail    string
	resetEmail      string
	clearedCooldown string
	clearedSend     string
	setCooldownErr  error
}

func newOTPRepoTestDouble() *otpRepoTestDouble {
	return &otpRepoTestDouble{
		otp:      map[string]string{},
		attempts: map[string]int{},
	}
}

func (m *otpRepoTestDouble) SetOTP(ctx context.Context, email, hashed string, ttl time.Duration) error {
	m.otp[email] = hashed
	return nil
}
func (m *otpRepoTestDouble) GetOTP(ctx context.Context, email string) (string, error) {
	hashed, ok := m.otp[email]
	if !ok {
		return "", redis.Nil
	}
	return hashed, nil
}
func (m *otpRepoTestDouble) DeleteOTP(ctx context.Context, email string) error {
	m.deletedEmail = email
	delete(m.otp, email)
	return nil
}
func (m *otpRepoTestDouble) IncrementAttempts(ctx context.Context, email string, ttl time.Duration) (int, error) {
	m.attempts[email]++
	return m.attempts[email], nil
}
func (m *otpRepoTestDouble) ResetAttempts(ctx context.Context, email string) error {
	m.resetEmail = email
	delete(m.attempts, email)
	return nil
}
func (m *otpRepoTestDouble) SetCooldown(ctx context.Context, email string, ttl time.Duration) error {
	return m.setCooldownErr
}
func (m *otpRepoTestDouble) GetCooldownTTL(ctx context.Context, email string) (time.Duration, error) {
	return m.cooldownTTL, nil
}
func (m *otpRepoTestDouble) ClearCooldown(ctx context.Context, email string) error {
	m.clearedCooldown = email
	return nil
}
func (m *otpRepoTestDouble) IncrementSendCount(ctx context.Context, email string, ttl time.Duration) (int, time.Duration, error) {
	m.sendCount++
	return m.sendCount, m.sendRetryAfter, nil
}
func (m *otpRepoTestDouble) ClearSendCount(ctx context.Context, email string) error {
	m.clearedSend = email
	return nil
}

type otpSenderTestDouble struct {
	to      string
	code    string
	appName string
	err     error
}

func (m *otpSenderTestDouble) SendOTP(to, code, appName string) error {
	m.to = to
	m.code = code
	m.appName = appName
	return m.err
}

func otpTestConfig() config.OTPConfig {
	return config.OTPConfig{
		TTL:         5 * time.Minute,
		MaxAttempts: 2,
		RateLimit:   2,
		RateWindow:  time.Minute,
		Cooldown:    time.Minute,
		Secret:      "secret",
	}
}

func TestSendRegisterOTPStoresHashedOTPAndSendsNormalizedEmail(t *testing.T) {
	repo := newOTPRepoTestDouble()
	sender := &otpSenderTestDouble{}
	svc := NewOTPService(repo, sender, otpTestConfig())

	if err := svc.SendRegisterOTP(context.Background(), " Jane.Doe@Example.COM ", "Starter"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if sender.to != "jane.doe@example.com" || sender.appName != "Starter" {
		t.Fatalf("unexpected sender call: %+v", sender)
	}
	if len(sender.code) != 6 {
		t.Fatalf("expected six digit code, got %q", sender.code)
	}
	if repo.otp["jane.doe@example.com"] == "" || repo.otp["jane.doe@example.com"] == sender.code {
		t.Fatalf("expected hashed otp to be stored, got %q", repo.otp["jane.doe@example.com"])
	}
}

func TestSendRegisterOTPReturnsThrottleOnCooldown(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.cooldownTTL = 30 * time.Second
	svc := NewOTPService(repo, &otpSenderTestDouble{}, otpTestConfig())

	err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	var throttle *ThrottleError
	if !errors.As(err, &throttle) {
		t.Fatalf("expected throttle error, got %v", err)
	}
	if throttle.Reason != "cooldown" || throttle.RetryAfter != 30*time.Second {
		t.Fatalf("unexpected throttle error: %+v", throttle)
	}
}

func TestSendRegisterOTPCleansUpWhenDeliveryFails(t *testing.T) {
	repo := newOTPRepoTestDouble()
	svc := NewOTPService(repo, &otpSenderTestDouble{err: errors.New("smtp down")}, otpTestConfig())

	err := svc.SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	if !errors.Is(err, ErrOTPDeliveryFailed) {
		t.Fatalf("expected delivery failed error, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" || repo.clearedCooldown != "jane@example.com" || repo.clearedSend != "jane@example.com" {
		t.Fatalf("expected cleanup for failed delivery, got %+v", repo)
	}
}

func TestVerifyRegisterOTPSucceedsAndClearsState(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.otp["jane@example.com"] = hashOTP("123456", "secret")
	svc := NewOTPService(repo, nil, otpTestConfig())

	if err := svc.VerifyRegisterOTP(context.Background(), " Jane@Example.COM ", " 123456 "); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" || repo.resetEmail != "jane@example.com" || repo.clearedSend != "jane@example.com" {
		t.Fatalf("expected otp state cleared, got %+v", repo)
	}
}

func TestVerifyRegisterOTPDeletesAfterTooManyAttempts(t *testing.T) {
	repo := newOTPRepoTestDouble()
	repo.otp["jane@example.com"] = hashOTP("123456", "secret")
	repo.attempts["jane@example.com"] = 2
	svc := NewOTPService(repo, nil, otpTestConfig())

	err := svc.VerifyRegisterOTP(context.Background(), "jane@example.com", "000000")
	if !errors.Is(err, ErrOTPTooManyAttempt) {
		t.Fatalf("expected too many attempts, got %v", err)
	}
	if repo.deletedEmail != "jane@example.com" {
		t.Fatalf("expected otp deleted, got %+v", repo)
	}
}

func TestOTPServiceNotConfigured(t *testing.T) {
	err := NewOTPService(nil, nil, otpTestConfig()).SendRegisterOTP(context.Background(), "jane@example.com", "Starter")
	if !errors.Is(err, ErrOTPNotConfigured) {
		t.Fatalf("expected not configured error, got %v", err)
	}
}
