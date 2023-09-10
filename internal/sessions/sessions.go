package sessions

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/errors"
	"github.com/thxgg/watermelon/internal/validator"
)

const (
	CookieName   = "sessionID"
	ContextEntry = "session"
)

type Config struct {
	DatabaseURL string `validate:"url"`
	Duration    time.Duration
}

type Session struct {
	UserID       uuid.UUID `redis:"-"`
	UserIDString string    `redis:"user_id_string"`
	IsAdmin      bool      `redis:"is_admin"`
}

func NewAuthMiddleware(config *Config) (func(*fiber.Ctx) error, error) {
	sessionsDB, err := database.NewRedisDatabase(&database.Config{URL: config.DatabaseURL})
	if err != nil {
		return nil, err
	}

	return func(c *fiber.Ctx) error {
		sessionID := c.Cookies(CookieName)

		err := validator.New().Var(sessionID, "required,uuid4")
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
				Error: "Invalid session ID",
			})
		}

		exists := sessionsDB.Exists(context.Background(), sessionID)
		if exists.Err() != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid session ID",
			})
		}

		sessionMap := sessionsDB.HGetAll(context.Background(), sessionID)
		if sessionMap.Err() != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
				Error: "Invalid session ID",
			})
		}

		var session Session
		err = sessionMap.Scan(&session)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
				Error: "Invalid session ID",
			})
		}
		userID, err := uuid.Parse(session.UserIDString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
				Error: "Invalid session ID",
			})
		}
		session.UserID = userID

		c.Locals(ContextEntry, session)
		return c.Next()
	}, nil
}
