package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func FiberMiddleware(a *fiber.App) {
	log.Debug("Setting up Fiber middleware")
	a.Use(
		cors.New(),
		logger.New(logger.Config{
			Format:   "[${time}] [${pid}] ${status} - ${latency} ${method} ${path} ${error}\n",
			TimeZone: "UTC",
		}),
	)
}
