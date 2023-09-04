package middleware

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/utils"
	"github.com/thxgg/watermelon/internal/validator"
)

var SessionsDB *redis.Client

func init() {
	log.Debug("Setting up sessions database")
	opt, err := redis.ParseURL(config.Config.Sessions.Database)
	if err != nil {
		log.Fatal("Failed to parse sessions database URL")
	}

	SessionsDB = redis.NewClient(opt)
}

func Protected() func(*fiber.Ctx) error {
	log.Debug("Setting up sessions middleware")

	return func(c *fiber.Ctx) error {
		sessionID := c.Cookies("sessionID")

		err := validator.Validator.Var(sessionID, "required,uuid4")
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
				Error:   true,
				Message: "Invalid session ID",
			})
		}

		exists := SessionsDB.Exists(context.Background(), sessionID)
		if exists.Err() != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
				Error:   true,
				Message: "Invalid session ID",
			})
		}

		sessionMap := SessionsDB.HGetAll(context.Background(), sessionID)
		if sessionMap.Err() != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
				Error:   true,
				Message: "Invalid session ID",
			})
		}

		var session utils.Session
		err = sessionMap.Scan(&session)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
				Error:   true,
				Message: "Invalid session ID",
			})
		}
		userID, err := uuid.Parse(session.UserIDString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
				Error:   true,
				Message: "Invalid session ID",
			})
		}
		session.UserID = userID

		c.Locals("session", session)

		return c.Next()
	}
}
