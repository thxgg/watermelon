package utils

type APIError struct {
	Error bool   `json:"error"`
	Msg   string `json:"msg"`
}
