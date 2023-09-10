#!/usr/bin/env sh

no_migrations_flag=false

while [ $# -gt 0 ]; do
  case "$1" in
    -no-migrations)
      no_migrations_flag=true
      ;;
  esac
  shift
done

if [ "$no_migrations_flag" = false ]; then
  echo "Running database migrations"
  godotenv -f ".env.test" tern migrate --config ./internal/database/migrations/tern.conf --migrations ./internal/database/migrations
  echo "Database migrations complete"
fi

log_flag=false

while [ $# -gt 0 ]; do
  case "$1" in
    -log)
      log_flag=true
      ;;
  esac
  shift
done

if [ "$log_flag" = true ]; then
  export WATERMELON_TEST_LOG=true
fi

export WATERMELON_ENV=test
godotenv -f ".env.test" go test -v ./... -count=1 -cover -coverprofile=coverage.out
