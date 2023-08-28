package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/georgysavva/scany/v2/pgxscan"
	_ "github.com/joho/godotenv/autoload"
	"github.com/thxgg/watermelon/internal/auth"
	"github.com/thxgg/watermelon/internal/database"
)

func main() {
	// Database
	if err := database.ConnectToDB(); err != nil {
		log.Fatalln("Failed to connect to the database")
	}
	defer database.DB.Close()

	var user auth.User
	err := pgxscan.Get(context.Background(), database.DB, &user, `SELECT * FROM users WHERE username = 'thxgg'`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(user)
}
