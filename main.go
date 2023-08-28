package main

import (
	"context"
	"fmt"
	"os"

	"github.com/georgysavva/scany/v2/pgxscan"
	uuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/joho/godotenv/autoload"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
)

func main() {
	// Open connection to DB
	ctx := context.Background()
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create connection pool: %v\n", err)
		os.Exit(1)
	}

	// Register UUID data type
	db.Config().AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	defer db.Close()

	type UserRole string

	const (
		User  UserRole = "USER"
		Admin UserRole = "ADMIN"
	)

	var user struct {
		Id       uuid.UUID
		Email    string
		Password string
		Role     UserRole
		Username string
		Verified bool
	}
	err = pgxscan.Get(ctx, db, &user, `SELECT * FROM users WHERE username = 'thxgg'`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(user)
}
