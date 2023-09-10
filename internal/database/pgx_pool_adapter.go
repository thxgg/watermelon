package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxPoolAdapter implements the Database interface for pgxpool.Pool
type PgxPoolAdapter struct {
	Pool *pgxpool.Pool
}

func (p *PgxPoolAdapter) Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error) {
	return p.Pool.Exec(ctx, sql, arguments...)
}

func (p *PgxPoolAdapter) Query(ctx context.Context, sql string, arguments ...interface{}) (pgx.Rows, error) {
	return p.Pool.Query(ctx, sql, arguments...)
}

func (p *PgxPoolAdapter) QueryRow(ctx context.Context, sql string, arguments ...interface{}) pgx.Row {
	return p.Pool.QueryRow(ctx, sql, arguments...)
}

func (p *PgxPoolAdapter) Close() {
	p.Pool.Close()
}
