package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/controllers"
	"github.com/thxgg/watermelon/internal/middleware"
)

func PrivateRoutes(a fiber.Router) {
	log.Debug("Setting up private routes")
	// Auth
	a.Delete("/logout", middleware.Protected(), controllers.Logout)

	// Me
	meGroup := a.Group("/me", middleware.Protected())
	meGroup.Get("/", controllers.GetSelf)
	meGroup.Put("/", controllers.UpdateSelf)
	meGroup.Put("/password", controllers.ChangePassword)
	meGroup.Delete("/", controllers.DeleteSelf)

	// Users
	userGroup := a.Group("/users", middleware.Protected())
	userGroup.Get("/", controllers.GetUsers)
	userGroup.Get("/:id", controllers.GetUser)
	userGroup.Put("/:id", controllers.UpdateUser)
	userGroup.Delete("/:id", controllers.DeleteUser)
}
