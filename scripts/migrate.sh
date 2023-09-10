#!/usr/bin/env sh

echo "Running database migrations"
tern migrate --config ./internal/database/migrations/tern.conf --migrations ./internal/database/migrations
echo "Database migrations complete"
