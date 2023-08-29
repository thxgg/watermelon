package utils

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

func StartServer(a *fiber.App) {
	log.Fatal(a.Listen(":8080"))
}
