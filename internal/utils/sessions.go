package utils

import "github.com/google/uuid"

type Session struct {
	UserID       uuid.UUID `redis:"-"`
	UserIDString string    `redis:"user_id_string"`
	IsAdmin      bool      `redis:"is_admin"`
}
