package test_utils

import (
	"io"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/server"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/email"
)

func init() {
	// Change working directory to the root of the project
	os.Chdir("../..")
	if os.Getenv("WATERMELON_TEST_LOG") != "true" {
		// Disable logging
		log.SetOutput(io.Discard)
	}
}

// SetupTest is run before each test function and sets up the test environment
func SetupTest(t *testing.T) *server.Server {
	config := config.New()

	db, err := database.NewPostgresDatabase(&config.Database)
	if err != nil {
		log.Fatal("Failed to connect to the database")
	}
	t.Cleanup(func() {
		db.Close()
	})

	redisDB, err := database.NewRedisDatabase(&database.Config{URL: config.Session.DatabaseURL})
	if err != nil {
		log.Fatal("Failed to connect to the sessions database")
	}
	t.Cleanup(func() {
		redisDB.Close()
	})

	emailClient, err := email.NewClient(&config.Email)
	if err != nil {
		log.Fatal("Failed to setup email client")
	}
	t.Cleanup(func() {
		emailClient.Close()
	})

	server := server.New(&server.Config{
		Global:      config,
		DB:          db,
		SessionsDB:  redisDB,
		EmailClient: emailClient,
	})
	t.Cleanup(func() {
		server.Shutdown()
	})

	return server
}
