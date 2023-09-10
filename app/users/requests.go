package users

// UserUpdateRequest represents the request body for updating a user
type UserUpdateRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username" validate:"required,min=3,max=32"`
}

// ChangePasswordRequest represents the request body for changing a user's password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required,min=8,max=32"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=32,nefield=OldPassword"`
}
