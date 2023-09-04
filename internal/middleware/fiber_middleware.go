package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func FiberMiddleware(a *fiber.App) {
	log.Debug("Setting up Fiber middleware")
	a.Use(
		cors.New(),
		recover.New(),
		logger.New(logger.Config{
			Format:   "{ \"timestamp\": \"${time}\", \"pid\": \"${pid}\", \"status\": \"${status}\", \"latency\": \"${latency}\", \"method\": \"${method}\", \"path\": \"${path}\", \"error\": \"${error}\" }\n",
			TimeZone: "UTC",
		}),
	)
}
