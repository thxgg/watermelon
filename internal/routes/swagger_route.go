package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/swagger"
	_ "github.com/thxgg/watermelon/docs"
)

func SwaggerRoute(a fiber.Router) {
	log.Debug("Setting up Swagger route")
	a.Get("/swagger/*", swagger.HandlerDefault)
}
