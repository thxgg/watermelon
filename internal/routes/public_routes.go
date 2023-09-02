package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/thxgg/watermelon/app/controllers"
)

func PublicRoutes(a fiber.Router) {
	// Auth
	a.Post("/register", controllers.Register)
	a.Post("/login", controllers.Login)
}
