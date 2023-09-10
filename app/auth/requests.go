package auth

import "github.com/google/uuid"

// RegisterRequest represents the data needed to register a new user
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=32"`
	Username string `json:"username" validate:"required,min=3,max=32"`
}

// LoginRequest represents the data needed to login a user
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=32"`
}

// ResetPasswordRequest represents the data needed to reset a user's password
type ResetPasswordRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required,uuid4"`
	Token    uuid.UUID `json:"token" validate:"required,uuid4"`
	Password string    `json:"password" validate:"required,min=8,max=32"`
}
