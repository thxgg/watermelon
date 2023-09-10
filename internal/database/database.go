package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
)

type Config struct {
	URL              string `validate:"url"`
	PreferConnection bool
}

type Database interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Close()
}

func NewPostgresDatabase(config *Config) (Database, error) {
	var db Database
	var err error

	ctx := context.Background()
	if config.PreferConnection {
		conn, err := pgx.Connect(ctx, config.URL)
		if err != nil {
			return nil, err
		}
		conn.Config().AfterConnect = func(ctx context.Context, pgconn *pgconn.PgConn) error {
			pgxuuid.Register(conn.TypeMap())
			return nil
		}
		db = &PgxConnAdapter{Conn: conn}
	} else {
		pool, err := pgxpool.New(ctx, config.URL)
		if err != nil {
			return nil, err
		}
		pool.Config().AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			pgxuuid.Register(conn.TypeMap())
			return nil
		}
		db = &PgxPoolAdapter{Pool: pool}
	}

	return db, err
}

func NewRedisDatabase(config *Config) (*redis.Client, error) {
	opt, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, err
	}

	return redis.NewClient(opt), nil
}
