package config

import (
	"os"

	"github.com/gofiber/fiber/v2/log"
	"github.com/spf13/viper"
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
	configName := "watermelon"
	if os.Getenv("WATERMELON_ENV") == "test" {
		configName = "test.watermelon"
	}
	viper.SetConfigName(configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalf("Couldn't read config file: %w", err)
	}

	var config *Global
	err = viper.Unmarshal(&config)
	if err != nil {
		log.Fatalf("Couldn't unmarshal config file: %v", err)
	}

	err = validator.New().Struct(config)
	if err != nil {
		log.Panicf("Failed to validate configuration: %s", err)
	}

	return config
}
