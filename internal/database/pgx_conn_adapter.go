package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PgxConnAdapter implements the Database interface for pgx.Conn
type PgxConnAdapter struct {
	Conn *pgx.Conn
}

func (c *PgxConnAdapter) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
	return c.Conn.Exec(ctx, sql, arguments...)
}

func (c *PgxConnAdapter) Query(ctx context.Context, sql string, arguments ...interface{}) (pgx.Rows, error) {
	return c.Conn.Query(ctx, sql, arguments...)
}

func (c *PgxConnAdapter) QueryRow(ctx context.Context, sql string, arguments ...interface{}) pgx.Row {
	return c.Conn.QueryRow(ctx, sql, arguments...)
}

func (c *PgxConnAdapter) Close() {
	c.Conn.Close(context.Background())
}
