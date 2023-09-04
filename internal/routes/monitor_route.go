package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/monitor"
)

func MonitorRoute(r fiber.Router) {
	log.Debug("Setting up monitor routes")
	r.Get("/metrics", monitor.New(monitor.Config{
		Title:   "Watermelon Monitor",
		FontURL: "https://fonts.cdnfonts.com/css/clear-sans",
	}))
}
