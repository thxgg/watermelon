package config

import (
	"os"
	"strconv"

	_ "github.com/joho/godotenv/autoload"
	"github.com/thxgg/watermelon/internal/utils"
)

type JWTConfig struct {
	Secret   string
	Database string `validate:"url"`
	Lifetime int
}

type config struct {
	Database string `validate:"url"`
	JWT      JWTConfig
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

	err = utils.Validator.Struct(Config)
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
