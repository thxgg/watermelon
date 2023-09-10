package server

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/swagger"
	"github.com/thxgg/watermelon/app/auth"
	"github.com/thxgg/watermelon/app/users"
	_ "github.com/thxgg/watermelon/docs"
	"github.com/thxgg/watermelon/internal/sessions"
)

func (s *Server) RegisterRoutes() {
	r := s.Group("/api")
	authMiddleware, err := sessions.NewAuthMiddleware(&s.Config.Session)
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %s", err)
	}

	r.Get("/monitor", monitor.New(monitor.Config{
		Title:   "Watermelon Monitor",
		FontURL: "https://fonts.cdnfonts.com/css/clear-sans",
	}))
	r.Get("/swagger/*", swagger.HandlerDefault)

	authController := auth.Controller{
		Config:      s.Config.Global,
		Repository:  users.Repository{Database: s.Config.DB},
		SessionsDB:  s.Config.SessionsDB,
		EmailClient: s.Config.EmailClient,
	}
	r.Post("/register", authController.Register)
	r.Post("/login", authController.Login)
	r.Post("/forgotten-password", authController.ForgottenPassword)
	r.Post("/reset-password", authController.ResetPassword)
	r.Delete("/logout", authMiddleware, authController.Logout)

	usersController := users.Controller{
		Repository: users.Repository{Database: s.Config.DB},
	}
	meGroup := r.Group("/me", authMiddleware)
	meGroup.Get("/", usersController.GetSelf)
	meGroup.Put("/", usersController.UpdateSelf)
	meGroup.Put("/password", usersController.ChangePassword)
	meGroup.Delete("/", usersController.DeleteSelf)

	userGroup := r.Group("/users", authMiddleware)
	userGroup.Get("/", usersController.GetUsers)
	userGroup.Get("/:id", usersController.GetUser)
	userGroup.Put("/:id", usersController.UpdateUser)
	userGroup.Delete("/:id", usersController.DeleteUser)
	r.Put("/verify", usersController.VerifyUserEmail)

	r.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404)
	})
}
