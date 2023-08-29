# Project: Watermelon

This project is the first of the PGV stack (Postgres, Go, Vue).

## File structure

- `app`: business logic
- `docs`: non-code documentation (e.g. design documents, Swagger)
- `internal`: server setup logic (e.g. middlware, routing)
- `platform`: platform-level configuration (e.g. database connection, database migrations)
- `scripts`: scripts for builds, installs, analysis, etc.
- `website`: the web client

## Database

PostgreSQL database managed by [Railway](https://railway.app/).

### Driver

[pgx](https://github.com/jackc/pgx) is the Go driver of choice for communication with the database.

### Migrations

Database migrations are handled by [tern](https://github.com/jackc/tern). All relevant migration files (including configuration and the migration scripts themselves) are stored in `platform/migrations`. To migrate, ensure the `DATABASE_URL` env var is set to the connection string to the database and run

```sh
export $DATABASE_URL
./scripts/migrate.sh
```

### Scanning

[scany](https://github.com/georgysavva/scany) is the library of choice for scanning database data to Go structs and slices.

## Server

The server is built using the Go [Fiber](https://github.com/gofiber/fiber) framework.

### Swagger

API documentation is handled by [Swagger](https://github.com/gofiber/swagger). To generate latest API docs, run `./scripts/swagger.sh`.
