package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/thxgg/watermelon/app/controllers"
)

func PublicRoutes(a *fiber.App) {
	// Auth
	// a.Post("/register", controllers.Register)
	// a.Post("/login", controllers.Login)

	// Users
	userGroup := a.Group("/users")
	userGroup.Get("/", controllers.GetUsers)
	userGroup.Get("/:id", controllers.GetUser)
}
