package config

import (
	"os"
	"strconv"

	_ "github.com/joho/godotenv/autoload"
)

type JWTConfig struct {
	Secret   string
	Database string
	Lifetime int
}

var Config struct {
	Database string
	JWT      JWTConfig
}

func init() {
	Config = struct {
		Database string
		JWT      JWTConfig
	}{}

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
}

func loadEnvVar(key string) string {
	value, present := os.LookupEnv(key)
	if !present {
		panic(key + " environment variable is not set")
	}

	return value
}
