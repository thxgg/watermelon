package server

import (
	"os"

	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func (s *Server) RegisterMiddleware() {
	s.Use(
		cors.New(),
		recover.New(),
	)

	if os.Getenv("WATERMELON_ENV") == "test" && os.Getenv("WATERMELON_TEST_LOG") != "true" {
		return
	}

	s.Use(
		logger.New(logger.Config{
			Format:   "{ \"timestamp\": \"${time}\", \"pid\": \"${pid}\", \"status\": \"${status}\", \"latency\": \"${latency}\", \"method\": \"${method}\", \"path\": \"${path}\", \"error\": \"${error}\" }\n",
			TimeZone: "UTC",
		}),
	)
}
