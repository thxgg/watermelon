package config

import (
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2/log"
	_ "github.com/joho/godotenv/autoload"
	"github.com/thxgg/watermelon/internal/validator"
)

type SessionConfig struct {
	Database string `validate:"url"`
	Duration time.Duration
}

type EmailConfig struct {
	Host     string `validate:"hostname"`
	Port     int
	Username string
	Password string
	From     string `validate:"email"`
}

type config struct {
	Database string `validate:"url"`
	Sessions SessionConfig
	Email    EmailConfig
	BaseURL  string `validate:"url"`
}

var Config config

func init() {
	log.Debug("Loading configuration")
	// Database
	Config.Database = loadEnvVar("DATABASE_URL")

	// Sessions
	sessionsDuration, err := strconv.Atoi(loadEnvVar("SESSION_DURATION_HOURS"))
	if err != nil {
		log.Panicf("Failed to parse sessions duration: %s", err)
	}
	Config.Sessions = SessionConfig{
		Database: loadEnvVar("SESSION_DATABASE_URL"),
		Duration: time.Duration(sessionsDuration),
	}

	// Email
	smtpPort, err := strconv.Atoi(loadEnvVar("SMTP_PORT"))
	if err != nil {
		log.Panicf("Failed to parse SMTP port: %s", err)
	}
	Config.Email = EmailConfig{
		Host:     loadEnvVar("SMTP_HOST"),
		Port:     smtpPort,
		Username: loadEnvVar("SMTP_USERNAME"),
		Password: loadEnvVar("SMTP_PASSWORD"),
		From:     loadEnvVar("SMTP_FROM"),
	}

	// App
	Config.BaseURL = loadEnvVar("BASE_URL")

	err = validator.Validator.Struct(Config)
	if err != nil {
		log.Panicf("Failed to validate configuration: %s", err)
	}
}

func loadEnvVar(key string) string {
	value, present := os.LookupEnv(key)
	if !present {
		log.Panicf("Environment variable %s not set", key)
	}

	return value
}
