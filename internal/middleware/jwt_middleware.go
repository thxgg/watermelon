package middleware

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/config"

	jwtware "github.com/gofiber/contrib/jwt"
)

var JWT_DB *redis.Client

func init() {
	opt, err := redis.ParseURL(config.Config("JWT_REDIS_URL"))
	if err != nil {
		panic(err)
	}

	JWT_DB = redis.NewClient(opt)
}

func Protected() func(*fiber.Ctx) error {
	config := jwtware.Config{
		SigningKey:   jwtware.SigningKey{Key: []byte(config.Config("JWT_SECRET_KEY"))},
		ErrorHandler: jwtError,
	}

	return jwtware.New(config)
}

func jwtError(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": true,
		"msg":   err.Error(),
	})
}

func ValidateJWT(token *jwt.Token) (*uuid.UUID, error) {
	exp, err := token.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	if exp.Before(time.Now()) {
		return nil, jwt.ErrTokenExpired
	}

	err = JWT_DB.Get(context.Background(), token.Raw).Err()
	if err != nil {
		return nil, err
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return nil, err
	}

	id, err := uuid.Parse(sub)
	if err != nil {
		return nil, err
	}

	return &id, nil
}
