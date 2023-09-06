package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/routes"
	"github.com/thxgg/watermelon/internal/utils"
	"github.com/thxgg/watermelon/internal/validator"
	"github.com/thxgg/watermelon/platform/database"
)

// @title Watermelon API
// @version 1.0
// @description This is the API for Watermelon
// @contact.name Georgi Georgiev
// @contact.email gatanasovgeorgiev@gmail.com
// @BasePath /api
// @securityDefinitions.apikey SessionID
// @in cookie
// @name sessionID
// @description This is the session ID
func main() {
	// Setup config
	config.Setup()

	// Setup validator
	validator.Setup()

	// Connect to the database
	err := database.Connect()
	if err != nil {
		log.Fatal("Failed to connect to the database")
	}
	defer database.DB.Close()

	// Connect to the sessions database
	err = database.ConnectSessionsDB()
	if err != nil {
		log.Fatal("Failed to connect to the sessions database")
	}
	defer database.SessionsDB.Close()

	// Setup email client
	err = email.SetupEmailClient()
	if err != nil {
		log.Fatal("Failed to setup email client")
	}
	defer email.CloseEmailClient()

	// Configure the Fiber app
	app := fiber.New()

	// Setup Fiber middleware
	middleware.FiberMiddleware(app)

	// Setup routes
	log.Debug("Setting up routes")
	api := app.Group("/api")
	routes.SwaggerRoute(api)
	routes.MonitorRoute(api)
	routes.PublicRoutes(api)
	routes.PrivateRoutes(api)
	routes.NotFoundRoute(api)

	// Start Fiber server
	utils.StartServer(app)
}
