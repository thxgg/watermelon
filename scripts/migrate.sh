#!/usr/bin/env sh

echo "Running database migrations"
tern migrate --config ./platform/migrations/tern.conf --migrations ./platform/migrations
echo "Database migrations complete"
