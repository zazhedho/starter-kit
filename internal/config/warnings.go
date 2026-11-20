package config

import "strings"

// Warnings lists settings that are valid but unsafe. Each names its variable and
// never the value; the app logs them at startup.
func (c Config) Warnings() []string {
	var warnings []string
	if c.Media.Enabled && !c.Redis.Configured() {
		warnings = append(warnings, "MEDIA_ENABLED is true without Redis: uploads are not rate limited")
	}
	for _, secret := range []struct{ key, value string }{
		{"JWT_KEY", c.Auth.JWTKey}, {"DB_PASS", c.Database.Password}, {"REDIS_PASSWORD", c.Redis.Password},
		{"OTP_SECRET", c.Auth.OTP.Secret}, {"RESET_SECRET", c.Auth.Reset.Secret}, {"SMTP_PASS", c.SMTP.Password},
		{"STORAGE_ACCESS_KEY", c.Storage.AccessKey}, {"STORAGE_SECRET_KEY", c.Storage.SecretKey},
	} {
		if isPlaceholder(secret.value) {
			warnings = append(warnings, secret.key+" holds a placeholder or well-known default value: set a real secret")
		}
	}
	return warnings
}

// isPlaceholder recognizes the CHANGE_ME values of .env.example and the
// well-known defaults earlier examples used.
func isPlaceholder(value string) bool {
	v := normalizeKey(value)
	return strings.HasPrefix(v, "change_me") || strings.HasPrefix(v, "changeme") ||
		v == "your_password" || v == "minioadmin"
}
