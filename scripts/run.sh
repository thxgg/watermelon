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
  export WATERMELON_MIGRATE=true
else
  export WATERMELON_MIGRATE=false
fi

export WATERMELON_ENV=dev
go run main.go
