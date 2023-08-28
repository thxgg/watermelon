package auth

import "github.com/google/uuid"

type User struct {
	ID       uuid.UUID
	Email    string
	Password string
	Username string
	Verified bool
}
