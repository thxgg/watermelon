package middleware

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/config"

	jwtware "github.com/gofiber/contrib/jwt"
)

var JWT_DB *redis.Client

func init() {
	opt, err := redis.ParseURL(config.Config.JWT.Database)
	if err != nil {
		panic(err)
	}

	JWT_DB = redis.NewClient(opt)
}

func Protected() func(*fiber.Ctx) error {
	config := jwtware.Config{
		SigningKey:   jwtware.SigningKey{Key: []byte(config.Config.JWT.Secret)},
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

func ValidateJWT(token *jwt.Token) (jwt.MapClaims, error) {
	claims := token.Claims.(jwt.MapClaims)

	exp := claims["exp"].(float64)
	if time.Now().After(time.Unix(int64(exp), 0)) {
		return nil, jwt.ErrTokenExpired
	}

	err := JWT_DB.Get(context.Background(), token.Raw).Err()
	if err != nil {
		return nil, err
	}

	return claims, nil
}
