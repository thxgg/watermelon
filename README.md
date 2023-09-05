# Project: Watermelon

This project is the first of the PGV stack (Postgres, Go, Vue).

## File structure

- `app`: business logic
- `config`: application configuration
- `docs`: non-code documentation (e.g. design documents, Swagger)
- `internal`: server setup logic (e.g. middlware, routing, utilities)
- `platform`: platform-level configuration (e.g. database connection, database migrations)
- `scripts`: scripts for builds, installs, analysis, etc.
- `templates`: email templates
- `website`: the web client

## Configuration

Application configuration is automatically loaded and validated from environment variables and is accessible via the `config.Config` object. The following environment variables are required:
- `DATABASE_URL`: the connection string to the database
- `SESSION_DATABASE_URL`: the connection string to the Redis database
- `SESSION_DURATION_HOURS`: the number of hours a session token is valid for
- `SMTP_HOST`: the SMTP host to use for sending emails
- `SMTP_PORT`: the SMTP port to use for sending emails
- `SMTP_USERNAME`: the SMTP username to use for sending emails
- `SMTP_PASSWORD`: the SMTP password to use for sending emails
- `SMTP_FROM`: the email address to use for sending emails
- `BASE_URL`: the base URL of the server

## Database

A main [PostgreSQL](https://www.postgresql.org/) and a secondary [Redis](https://redis.io/) database managed by [Railway](https://railway.app/).

### Driver

[pgx](https://github.com/jackc/pgx) is the Go driver of choice for communication with the database.

### Migrations

Database migrations are handled by [tern](https://github.com/jackc/tern). All relevant migration files (including configuration and the migration scripts themselves) are stored in `platform/migrations`. To migrate, ensure the `DATABASE_URL` env var is set to the connection string to the database and run `scripts/migrate.sh`.

### Scanning

[scany](https://github.com/georgysavva/scany) is the library of choice for scanning database data to Go structs and slices.

## Server

The server is built using the Go [Fiber](https://github.com/gofiber/fiber) framework.

### Environment

Environment variables are loaded using the [godotenv](https://github.com/joho/godotenv) bin command.

### Swagger

API documentation is handled by [Swagger](https://github.com/gofiber/swagger). To generate latest API docs, run `scripts/swagger.sh`.

### Authentication

Authentication is handled by session tokens stored in the Redis database defined by `SESSION_DATABASE_URL`. The token is valid for a `SESSION_DURATION_HOURS` number of hours. The token is stored in a cookie and is sent with every request. The server will reject any request to a protected route that does not include a valid token.

### Validation

Validation is handled by [validator](https://github.com/go-playground/validator). All request bodies must include proper validation tags and are validated before being processed by the server.

### Email

Emails are sent using [go-mail](https://github.com/wneessen/go-mail). The SMTP configuration is defined by the `SMTP_*` environment variables. Templates are stored in the `templates` directory and are rendered using [html/template](https://pkg.go.dev/html/template).

## Testing

To run the tests, setup the `.env.test` file and run `scripts/test.sh`.

## Development

### Starting the server

To start the server, setup the `.env` file and run `scripts/run.sh`.
