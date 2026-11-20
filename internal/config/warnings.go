package config

import "strings"

// Warnings lists settings that are valid but unsafe. Each names its variable and
// never the value; the app logs them at startup.
func (c Config) Warnings() []string {
	var warnings []string
	if !c.Redis.Configured() {
		warnings = append(warnings, "Redis is not configured: public location reads (LOCATION_RATE_LIMIT) are not rate limited")
		if c.Media.Enabled {
			warnings = append(warnings, "MEDIA_ENABLED is true without Redis: uploads are not rate limited")
		}
	}
	if c.Media.Enabled && !c.Storage.UseSSL && !isR2(c.Storage.Provider) && !c.isDevelopment() {
		warnings = append(warnings, "STORAGE_USE_SSL is false: the storage keys and files cross the network in clear text")
	}
	if c.Media.Enabled && c.Storage.PublicRead && isR2(c.Storage.Provider) {
		warnings = append(warnings, "STORAGE_PUBLIC_READ has no effect with R2: make the bucket public in Cloudflare")
	}
	if c.isDevelopment() {
		for _, key := range c.placeholderSecrets() {
			warnings = append(warnings, key+" holds a placeholder or well-known default value: set a real secret")
		}
	}
	return warnings
}

// validatePlaceholders rejects placeholder secrets outside development, where
// they only warn.
func (c Config) validatePlaceholders() []string {
	if c.isDevelopment() {
		return nil
	}
	var problems []string
	for _, key := range c.placeholderSecrets() {
		problems = append(problems, key+" holds a placeholder or well-known default value: set a real secret")
	}
	return problems
}

// placeholderSecrets names the secrets that still hold an example value. The
// storage keys count only when media uses them.
func (c Config) placeholderSecrets() []string {
	secrets := []struct{ key, value string }{
		{"JWT_KEY", c.Auth.JWTKey}, {"DB_PASS", c.Database.Password}, {"REDIS_PASSWORD", c.Redis.Password},
		{"OTP_SECRET", c.Auth.OTP.Secret}, {"RESET_SECRET", c.Auth.Reset.Secret}, {"SMTP_PASS", c.SMTP.Password},
	}
	if c.Media.Enabled {
		secrets = append(secrets, struct{ key, value string }{"STORAGE_ACCESS_KEY", c.Storage.AccessKey},
			struct{ key, value string }{"STORAGE_SECRET_KEY", c.Storage.SecretKey})
	}
	var named []string
	for _, secret := range secrets {
		if isPlaceholder(secret.value) {
			named = append(named, secret.key)
		}
	}
	return named
}

// isPlaceholder recognizes the CHANGE_ME values of .env.example and the
// well-known defaults earlier examples used.
func isPlaceholder(value string) bool {
	v := normalizeKey(value)
	return strings.HasPrefix(v, "change_me") || strings.HasPrefix(v, "changeme") ||
		v == "your_password" || v == "minioadmin"
}
