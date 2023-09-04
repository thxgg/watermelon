package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/controllers"
)

func PublicRoutes(r fiber.Router) {
	log.Debug("Setting up public routes")
	// Auth
	r.Post("/register", controllers.Register)
	r.Post("/login", controllers.Login)
	r.Post("/forgotten-passowrd", controllers.ForgottenPassword)
	r.Post("/reset-password", controllers.ResetPassword)

	// Users
	r.Get("/users/:id/verify", controllers.VerifyUserEmail)
}
