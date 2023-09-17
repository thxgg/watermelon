# Project: Watermelon

This project is the first of the PGN stack (Postgres, Go, Nuxt).

## File structure

- `app`: business logic
- `config`: application configuration
- `docs`: non-code documentation (e.g. design documents, Swagger)
- `internal`: server setup logic (e.g. middlware, routing, utilities)
- `scripts`: scripts for builds, installs, analysis, etc.
- `templates`: email templates
- `website`: the web client

## Configuration

Application configuration is automatically loaded and validated from YAML files and is represented by the `config.Global` struct. And example of the available settings can be found in `watermelon.example.yaml`.

## Database

A main [PostgreSQL](https://www.postgresql.org/) and a secondary [Redis](https://redis.io/) database managed by [Railway](https://railway.app/).

### Driver

[pgx](https://github.com/jackc/pgx) is the Go driver of choice for communication with the database.

### Migrations

Database migrations are handled by [tern](https://github.com/jackc/tern). All relevant migration files (including configuration and the migration scripts themselves) are stored in `platform/migrations`. Upon starting the server via `scripts/run.sh` or testing via `scripts/test.sh` the migrations are automatically run. To migrate manually, ensure the `DATABASE_URL` env var is set to the connection string to the database and run `scripts/migrate.sh`.

### Scanning

[scany](https://github.com/georgysavva/scany) is the library of choice for scanning database data to Go structs and slices.

## Server

The server is built using the Go [Fiber](https://github.com/gofiber/fiber) framework.

### Environment

Environment variables are loaded using the [Viper](https://github.com/spf13/viper) library.

### Swagger

API documentation is handled by [Swaggo](https://github.com/swaggo/swag). To generate latest API docs, run `scripts/swagger.sh`.

### Authentication

Authentication is handled by session tokens stored in the Redis database. The token is stored in a cookie and is sent with every request. The server will reject any request to a protected route that does not include a valid token.

### Validation

Validation is handled by [validator](https://github.com/go-playground/validator). All request bodies must include proper validation tags and are validated before being processed by the server.

### Email

Emails are sent using [go-mail](https://github.com/wneessen/go-mail). Templates are stored in the `templates` directory and are rendered using [html/template](https://pkg.go.dev/html/template).

## Testing

To run the tests, setup the `test.watermelon.yaml` file and run `scripts/test.sh`. To run tests with logging enabled, run `scripts/test.sh -log`. To run the tests without database migrations, run `scripts/test.sh -no-migrations`. Boilerplate for setting up the server for testing is handled by `internal/testutils/test_setup.go`.

## Development

### Starting the server

To start the server, setup the `watermelon.yaml` file and run `scripts/run.sh`. To start the server without database migrations, run `scripts/run.sh -no-migrations`.

## Website

The website is built using the [Nuxt](https://nuxtjs.org/) framework. More information can be found in the [website README](website/README.md).
