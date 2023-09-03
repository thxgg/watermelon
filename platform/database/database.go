package database

import (
	"context"

	"github.com/gofiber/fiber/v2/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thxgg/watermelon/config"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
)

var DB *pgxpool.Pool

func Connect() error {
	log.Debug("Connecting to the database")
	// Open connection to DB
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, config.Config.Database)
	if err != nil {
		return err
	}

	// Register UUID data type
	pool.Config().AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}

	DB = pool
	return nil
}
