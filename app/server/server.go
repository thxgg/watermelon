package server

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/email"
)

type Config struct {
	*config.Global
	DB          database.Database
	SessionsDB  *redis.Client
	EmailClient *email.Client
}

type Server struct {
	*fiber.App
	Config *Config
}

func New(config *Config) *Server {
	server := &Server{
		App:    fiber.New(),
		Config: config,
	}

	server.RegisterMiddleware()
	server.RegisterRoutes()

	return server
}

func (s *Server) StartWithGracefulShutdown() {
	go func() {
		if err := s.Listen(s.Config.Port); err != nil {
			log.Panic(err)
		}
	}()

	c := make(chan os.Signal, 1)                    // Create channel to signify a signal being sent
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) // When an interrupt or termination signal is sent, notify the channel

	<-c // This blocks the main thread until an interrupt is received
	log.Println("Gracefully shutting down...")
	_ = s.Shutdown()

	log.Println("Running cleanup tasks...")
	s.Config.DB.Close()
	s.Config.SessionsDB.Close()
	s.Config.EmailClient.Close()

	log.Println("Fiber was successful shutdown.")
}
