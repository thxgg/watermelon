package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/controllers"
)

func PublicRoutes(a fiber.Router) {
	log.Debug("Setting up public routes")
	// Auth
	a.Post("/register", controllers.Register)
	a.Post("/login", controllers.Login)
	a.Post("/forgotten-passowrd", controllers.ForgottenPassword)
	a.Post("/reset-password", controllers.ResetPassword)

	// Users
	a.Get("/users/:id/verify", controllers.VerifyUserEmail)
}
