#!/usr/bin/env sh

echo "Running database migrations"
godotenv -f ".env.test" tern migrate --config ./platform/migrations/tern.conf --migrations ./platform/migrations
echo "Database migrations complete"

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
