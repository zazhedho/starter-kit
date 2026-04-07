package config

import (
	"strings"
	"time"

	"starter-kit/utils"
)

type PasswordResetConfig struct {
	TTL         time.Duration
	Cooldown    time.Duration
	RateWindow  time.Duration
	RateLimit   int
	Secret      string
	URLTemplate string
}

func LoadPasswordResetConfig() PasswordResetConfig {
	ttl := time.Duration(utils.GetEnv("RESET_TTL_SECONDS", 900)) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("RESET_TTL", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			ttl = parsed
		}
	}

	cooldown := time.Duration(utils.GetEnv("RESET_COOLDOWN_SECONDS", 60)) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("RESET_COOLDOWN", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cooldown = parsed
		}
	}

	rateWindow := time.Duration(utils.GetEnv("RESET_RATE_WINDOW_SECONDS", int(ttl.Seconds()))) * time.Second
	if value := strings.TrimSpace(utils.GetEnv("RESET_RATE_WINDOW", "")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			rateWindow = parsed
		}
	}

	urlTemplate := strings.TrimSpace(utils.GetEnv("RESET_URL_TEMPLATE", ""))
	if urlTemplate == "" {
		urlTemplate = strings.TrimSpace(utils.GetEnv("RESET_URL", ""))
	}

	return PasswordResetConfig{
		TTL:         ttl,
		Cooldown:    cooldown,
		RateWindow:  rateWindow,
		RateLimit:   utils.GetEnv("RESET_RATE_LIMIT", 5),
		Secret:      strings.TrimSpace(utils.GetEnv("RESET_SECRET", "reset-secret")),
		URLTemplate: urlTemplate,
	}
}
