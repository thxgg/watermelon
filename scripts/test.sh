#!/usr/bin/env sh

no_migrations_flag=false
log_flag=false

while [ $# -gt 0 ]; do
  case "$1" in
    -no-migrations)
      no_migrations_flag=true
      ;;
    -log)
      log_flag=true
      ;;
  esac
  shift
done

if [ "$no_migrations_flag" = false ]; then
  export WATERMELON_MIGRATE=true
else
  export WATERMELON_MIGRATE=false
fi

if [ "$log_flag" = false ]; then
  export WATERMELON_TEST_LOG=false
else
  export WATERMELON_TEST_LOG=true
fi

export WATERMELON_ENV=test
go test -v ./... -count=1 -cover -coverprofile=coverage.out
