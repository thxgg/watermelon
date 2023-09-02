package routes

import "github.com/gofiber/fiber/v2"

func NotFoundRoute(a fiber.Router) {
	a.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404) // => 404 "Not Found"
	})
}
