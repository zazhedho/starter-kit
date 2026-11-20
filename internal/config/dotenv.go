package config

import (
	"fmt"

	"github.com/joho/godotenv"
	"github.com/zazhedho/gokit"
)

func LoadDotEnv(path string) error {
	err := godotenv.Load(path)
	if err != nil && gokit.GetEnv("APP_ENV", "") == "" {
		return fmt.Errorf("load %s (and APP_ENV is not set): %w", path, err)
	}
	return nil
}
