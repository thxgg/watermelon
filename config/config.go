package config

import (
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/sessions"
	"github.com/thxgg/watermelon/internal/validator"
)

type Global struct {
	Database database.Config
	Session  sessions.Config
	Email    email.Config
	Port     string `validate:"hostname_port"`
	BaseURL  string `validate:"url"`
}

func New() *Global {
	config := &Global{
		Database: database.Config{
			URL:              loadEnvVar("DATABASE_URL"),
			PreferConnection: loadEnvVarBool("DATABASE_PREFER_CONNECTION"),
		},
		Session: sessions.Config{
			DatabaseURL: loadEnvVar("SESSION_DATABASE_URL"),
			Duration:    time.Duration(loadEnvVarInt("SESSION_DURATION_MINUTES")),
		},
		Email: email.Config{
			Host:     loadEnvVar("SMTP_HOST"),
			Port:     loadEnvVarInt("SMTP_PORT"),
			Username: loadEnvVar("SMTP_USERNAME"),
			Password: loadEnvVar("SMTP_PASSWORD"),
			From:     loadEnvVar("SMTP_FROM"),
			SSL:      loadEnvVarBool("SMTP_SSL"),
		},
		Port:    loadEnvVar("PORT"),
		BaseURL: loadEnvVar("BASE_URL"),
	}

	err := validator.New().Struct(config)
	if err != nil {
		log.Panicf("Failed to validate configuration: %s", err)
	}

	return config
}

func loadEnvVar(key string) string {
	value, present := os.LookupEnv(key)
	if !present {
		log.Panicf("Environment variable %s not set", key)
	}

	return value
}

func loadEnvVarInt(key string) int {
	value, err := strconv.Atoi(loadEnvVar(key))
	if err != nil {
		log.Panicf("Failed to parse environment variable %s as int: %s", key, err)
	}

	return value
}

func loadEnvVarBool(key string) bool {
	value, err := strconv.ParseBool(loadEnvVar(key))
	if err != nil {
		log.Panicf("Failed to parse environment variable %s as bool: %s", key, err)
	}

	return value
}
