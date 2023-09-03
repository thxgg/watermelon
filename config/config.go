package config

import (
	"os"
	"strconv"

	"github.com/gofiber/fiber/v2/log"
	_ "github.com/joho/godotenv/autoload"
	"github.com/thxgg/watermelon/internal/validator"
)

type JWTConfig struct {
	Secret   string
	Database string `validate:"url"`
	Lifetime int
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
	JWT      JWTConfig
	Email    EmailConfig
	BaseURL  string `validate:"url"`
}

var Config config

func init() {
	log.Debug("Loading configuration")
	Config.Database = loadEnvVar("DATABASE_URL")

	jwtLifetime, err := strconv.Atoi(loadEnvVar("JWT_LIFETIME_HOURS"))
	if err != nil {
		log.Panicf("Failed to parse JWT lifetime: %s", err)
	}
	Config.JWT = JWTConfig{
		Secret:   loadEnvVar("JWT_SECRET_KEY"),
		Database: loadEnvVar("JWT_REDIS_URL"),
		Lifetime: jwtLifetime,
	}

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
