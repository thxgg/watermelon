package models

import "github.com/google/uuid"

type User struct {
	ID       uuid.UUID `json:"id,omitempty"`
	Email    string    `json:"email,omitempty"`
	Password string    `json:"password,omitempty"`
	Username string    `json:"username,omitempty"`
	Verified bool      `json:"verified,omitempty"`
}
