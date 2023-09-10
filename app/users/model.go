package users

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         uuid.UUID `json:"id,omitempty"`
	Email      string    `json:"email,omitempty"`
	Password   string    `json:"-"`
	Username   string    `json:"username,omitempty"`
	IsAdmin    bool      `json:"is_admin,omitempty"`
	IsVerified bool      `json:"is_verified,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type UserEmailVerification struct {
	UserID uuid.UUID
	Token  uuid.UUID
}

type ForgottenPassword struct {
	UserID    uuid.UUID
	Token     uuid.UUID
	ExpiresAt time.Time
}
