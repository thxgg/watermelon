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
  godotenv -f ".env" tern migrate --config ./internal/database/migrations/tern.conf --migrations ./internal/database/migrations
  echo "Database migrations complete"
fi


godotenv -f ".env" go run main.go
