package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	_ "github.com/joho/godotenv/autoload"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/routes"
	"github.com/thxgg/watermelon/internal/utils"
	"github.com/thxgg/watermelon/platform/database"
)

// @title Watermelon API
// @version 1.0
// @description This is the API for Watermelon
// @contact.name Georgi Georgiev
// @contact.email gatanasovgeorgiev@gmail.com
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token
// @BasePath /
func main() {
	// Connect to the database
	err := database.Connect()
	if err != nil {
		log.Fatalln("Failed to connect to the database")
	}
	defer database.DB.Close()

	// Configure the Fiber app
	app := fiber.New()

	// Setup Fiber middleware
	middleware.FiberMiddleware(app)

	// Setup routes
	api := app.Group("/api")
	routes.SwaggerRoute(api)
	routes.PublicRoutes(api)
	routes.PrivateRoutes(api)
	routes.NotFoundRoute(api)

	// Start Fiber server
	utils.StartServer(app)
}
