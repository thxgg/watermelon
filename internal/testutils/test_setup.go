package test_utils

import (
	"io"
	"log"
	"os"
	"testing"

	"github.com/thxgg/watermelon/app/server"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/database/migrations"
	"github.com/thxgg/watermelon/internal/email"
)

func init() {
	// Change working directory to the root of the project (for email template resolution)
	os.Chdir("../..")
	log.Printf("Log: %s\n", os.Getenv("WATERMELON_TEST_LOG"))
	if os.Getenv("WATERMELON_TEST_LOG") != "true" {
		log.SetOutput(io.Discard)
	}
}

// SetupTest is run before each test function and sets up the test environment
func SetupTest(t *testing.T) *server.Server {
	config := config.New()

	if os.Getenv("WATERMELON_MIGRATE") == "true" {
		migrator, err := migrations.NewMigrator(config.Database.URL)
		if err != nil {
			log.Fatal("Failed to setup migrator")
		}
		err = migrator.Migrate()
		if err != nil {
			log.Fatal("Failed to migrate")
		}
		os.Unsetenv("WATERMELON_MIGRATE")
	}

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
