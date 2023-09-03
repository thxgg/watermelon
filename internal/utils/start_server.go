package utils

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
)

func StartServer(a *fiber.App) {
	log.Fatal(a.Listen(":8080"))
}
