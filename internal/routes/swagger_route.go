package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/swagger"
	_ "github.com/thxgg/watermelon/docs"
)

func SwaggerRoute(r fiber.Router) {
	log.Debug("Setting up Swagger route")
	r.Get("/swagger/*", swagger.HandlerDefault)
}
