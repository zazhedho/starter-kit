package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// LoadDotEnv loads path into the process environment without overriding
// variables that are already set. A missing or unreadable file is an error
// only when APP_ENV is not set, which is how containers that inject the
// environment run without a .env file.
func LoadDotEnv(path string) error {
	err := godotenv.Load(path)
	if err != nil && os.Getenv("APP_ENV") == "" {
		return fmt.Errorf("load %s (and APP_ENV is not set): %w", path, err)
	}
	return nil
}
