package main

import (
	"log"

	"github.com/thxgg/watermelon/app/server"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/database"
	"github.com/thxgg/watermelon/internal/email"
)

// @title												Watermelon API
// @version											1.0
// @description									This is the API for Watermelon
// @contact.name								Georgi Georgiev
// @contact.email								gatanasovgeorgiev@gmail.com
// @BasePath										/api
// @securityDefinitions.apikey	SessionID
// @in													cookie
// @name												sessionID
// @description									This is the session ID
func main() {
	// TODO: change config to use a yaml file
	config := config.New()

	db, err := database.NewPostgresDatabase(&config.Database)
	if err != nil {
		log.Fatal("Failed to connect to the database")
	}

	sessionsDB, err := database.NewRedisDatabase(&database.Config{URL: config.Session.DatabaseURL})
	if err != nil {
		log.Fatal("Failed to connect to the sessions database")
	}

	emailClient, err := email.NewClient(&config.Email)
	if err != nil {
		log.Fatal("Failed to setup email client")
	}

	server := server.New(&server.Config{
		Global:      config,
		DB:          db,
		SessionsDB:  sessionsDB,
		EmailClient: emailClient,
	})
	server.StartWithGracefulShutdown()
}
