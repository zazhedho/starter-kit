package config

import (
	"strings"
	"time"

	"starter-kit/utils"
)

type OTPConfig struct {
	TTL         time.Duration
	MaxAttempts int
	RateLimit   int
	RateWindow  time.Duration
	Cooldown    time.Duration
	Secret      string
}

func LoadOTPConfig() OTPConfig {
	ttl := time.Duration(utils.GetEnv("OTP_TTL_SECONDS", 300)) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("OTP_TTL", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			ttl = parsed
		}
	}

	cooldown := time.Duration(utils.GetEnv("OTP_COOLDOWN_SECONDS", 60)) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("OTP_COOLDOWN", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cooldown = parsed
		}
	}

	rateWindow := time.Duration(utils.GetEnv("OTP_RATE_WINDOW_SECONDS", int(ttl.Seconds()))) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("OTP_RATE_WINDOW", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			rateWindow = parsed
		}
	}

	return OTPConfig{
		TTL:         ttl,
		MaxAttempts: utils.GetEnv("OTP_MAX_ATTEMPTS", 5),
		RateLimit:   utils.GetEnv("OTP_RATE_LIMIT", 5),
		RateWindow:  rateWindow,
		Cooldown:    cooldown,
		Secret:      strings.TrimSpace(utils.GetEnv("OTP_SECRET", "otp-secret")),
	}
}
