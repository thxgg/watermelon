# Project: Watermelon

This project is the first of the PGV stack (Postgres, Go, Vue).

## Database

PostgreSQL database managed by [Railway](https://railway.app/).

### Driver

[pgx](https://github.com/jackc/pgx) is the Go driver of choice for communication with the database.

### Migrations

Database migrations are handled by [tern](https://github.com/jackc/tern). All relevant migration files (including configuration and the migration scripts themselves) are stored in `/migrations`. To migrate, ensure the `DATABASE_URL` env var is set to the connection string to the database and run the following command.

```sh
tern migrate --config migrations/tern.conf --migrations migrations
```
