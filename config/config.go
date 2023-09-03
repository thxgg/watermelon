package config

import (
	"os"
	"strconv"

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
}

var Config config

func init() {
	Config.Database = loadEnvVar("DATABASE_URL")

	jwtLifetime, err := strconv.Atoi(loadEnvVar("JWT_LIFETIME_HOURS"))
	if err != nil {
		panic(err)
	}
	Config.JWT = JWTConfig{
		Secret:   loadEnvVar("JWT_SECRET_KEY"),
		Database: loadEnvVar("JWT_REDIS_URL"),
		Lifetime: jwtLifetime,
	}

	smtpPort, err := strconv.Atoi(loadEnvVar("SMTP_PORT"))
	if err != nil {
		panic(err)
	}
	Config.Email = EmailConfig{
		Host:     loadEnvVar("SMTP_HOST"),
		Port:     smtpPort,
		Username: loadEnvVar("SMTP_USERNAME"),
		Password: loadEnvVar("SMTP_PASSWORD"),
		From:     loadEnvVar("SMTP_FROM"),
	}

	err = validator.Validator.Struct(Config)
	if err != nil {
		panic(err)
	}
}

func loadEnvVar(key string) string {
	value, present := os.LookupEnv(key)
	if !present {
		panic(key + " environment variable is not set")
	}

	return value
}
