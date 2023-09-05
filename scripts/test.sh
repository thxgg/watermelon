#!/usr/bin/env sh

godotenv -f ".env.test" go test -v ./... -count=1 -cover
