package test

import (
	"io"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/routes"
	"github.com/thxgg/watermelon/internal/validator"
	"github.com/thxgg/watermelon/platform/database"
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
func SetupTest(t *testing.T) *fiber.App {
	// Setup config
	config.Setup()

	// Setup validator
	validator.Setup()

	// Connect to the database
	err := database.Connect()
	if err != nil {
		log.Fatal("Failed to connect to the database")
	}
	t.Cleanup(func() {
		database.DB.Close()
	})

	// Connect to the sessions database
	err = database.ConnectSessionsDB()
	if err != nil {
		log.Fatal("Failed to connect to the sessions database")
	}
	t.Cleanup(func() {
		database.SessionsDB.Close()
	})

	// Setup email client
	err = email.SetupEmailClient()
	if err != nil {
		log.Fatal("Failed to setup email client")
	}
	t.Cleanup(func() {
		email.CloseEmailClient()
	})

	// Configure the Fiber app
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	t.Cleanup(func() {
		app.Shutdown()
	})

	// Setup Fiber middleware
	middleware.FiberMiddleware(app)

	// Setup routes
	api := app.Group("/api")
	routes.SwaggerRoute(api)
	routes.MonitorRoute(api)
	routes.PublicRoutes(api)
	routes.PrivateRoutes(api)
	routes.NotFoundRoute(api)

	return app
}
