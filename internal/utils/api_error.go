package utils

type APIError struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
}
