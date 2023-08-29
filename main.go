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
	routes.SwaggerRoute(app)
	routes.PublicRoutes(app)
	routes.PrivateRoutes(app)
	routes.NotFoundRoute(app)

	// Start Fiber server
	utils.StartServer(app)
}
