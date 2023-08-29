package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
	_ "github.com/thxgg/watermelon/docs"
)

func SwaggerRoute(a *fiber.App) {
	a.Get("/swagger/*", swagger.HandlerDefault)
}
