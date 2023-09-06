#!/usr/bin/env sh

echo "Running database migrations"
godotenv -f ".env" tern migrate --config ./platform/migrations/tern.conf --migrations ./platform/migrations
echo "Database migrations complete"

godotenv -f ".env" go run main.go
