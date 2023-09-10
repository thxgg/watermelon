package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/app/auth"
	"github.com/thxgg/watermelon/app/users"
	"github.com/thxgg/watermelon/internal/errors"
	"github.com/thxgg/watermelon/internal/sessions"
	test "github.com/thxgg/watermelon/internal/testutils"
	"golang.org/x/crypto/bcrypt"
)

// TestRegister tests the register endpoint
func TestRegister(t *testing.T) {
	server := test.SetupTest(t)

	method := "POST"
	url := "/api/register"
	// Test table for the register endpoint
	tests := []struct {
		name     string
		req      auth.RegisterRequest
		wantCode int
	}{
		{
			name:     "Empty email",
			req:      auth.RegisterRequest{Email: "", Password: "password", Username: "test_register"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed email",
			req:      auth.RegisterRequest{Email: "test_register@email", Password: "password", Username: "test_register"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "", Username: "test_register"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "passwor", Username: "test_register"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "passwordpasswordpasswordpasswordp", Username: "test_register"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty username",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "password", Username: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short username",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "password", Username: "us"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long username",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "password", Username: "usernameusernameusernameusernameu"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Valid request",
			req:      auth.RegisterRequest{Email: "test_register@email.com", Password: "password", Username: "test_register"},
			wantCode: fiber.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				_, err := server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", tt.req.Email)
				if err != nil {
					t.Error(err)
				}
			})

			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if res.StatusCode == fiber.StatusBadRequest || res.StatusCode == fiber.StatusInternalServerError {
				var errRes errors.APIError
				err := json.NewDecoder(res.Body).Decode(&errRes)
				if err != nil {
					t.Fatal(err)
				}

				if errRes.Error == "" {
					t.Errorf("Expected error to be true and a non-empty message, got %+v", errRes)
				}
			}

			// If the request was successful, check for the side effects
			if res.StatusCode == fiber.StatusCreated {
				// Session cookie
				cookies := res.Cookies()
				found := false

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						if !cookie.HttpOnly {
							t.Error("Expected session cookie to be HTTP only")
						}

						if !cookie.Secure {
							t.Error("Expected session cookie to be secure")
						}

						t.Cleanup(func() {
							server.Config.SessionsDB.HDel(context.Background(), cookie.Value)
						})

						found = true
						break
					}
				}

				if !found {
					t.Error("Expected a session cookie, got none")
				}

				// Email verification token
				var uev users.UserEmailVerification
				err := pgxscan.Get(context.Background(), server.Config.DB, &uev, "SELECT uev.* FROM user_email_verifications uev JOIN users u ON uev.user_id = u.id WHERE u.email=$1", tt.req.Email)
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestLogin tests the login endpoint
func TestLogin(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_login@email.com",
		Password: string(hashedPassword),
		Username: "test_login",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	method := "POST"
	url := "/api/login"
	// Test table for the login endpoint
	tests := []struct {
		name     string
		req      auth.LoginRequest
		wantCode int
	}{
		{
			name:     "Empty email",
			req:      auth.LoginRequest{Email: "", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed email",
			req:      auth.LoginRequest{Email: "test_login@email", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      auth.LoginRequest{Email: "test_login@email.com", Password: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      auth.LoginRequest{Email: "test_login@email.com", Password: "passwor"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      auth.LoginRequest{Email: "test_login@email.com", Password: "passwordpasswordpasswordpasswordp"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-existent user",
			req:      auth.LoginRequest{Email: "nonexistent@email.com", Password: "password"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Invalid credentials",
			req:      auth.LoginRequest{Email: "test_login@email.com", Password: "password1"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Valid request",
			req:      auth.LoginRequest{Email: testUser.Email, Password: testPassword},
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for the session cookie
			if res.StatusCode == fiber.StatusNoContent {
				cookies := res.Cookies()
				found := false

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						if !cookie.HttpOnly {
							t.Error("Expected session cookie to be HTTP only")
						}

						if !cookie.Secure {
							t.Error("Expected session cookie to be secure")
						}

						found = true
						t.Cleanup(func() {
							server.Config.SessionsDB.HDel(context.Background(), cookie.Value)
						})
						break
					}
				}

				if !found {
					t.Error("Expected a session cookie, got none")
				}
			}
		})
	}
}

// TestLogout tests the logout endpoint
func TestLogout(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_logout@email.com",
		Password: string(hashedPassword),
		Username: "test_logout",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Login
	method := "POST"
	url := "/api/login"

	body, _ := json.Marshal(auth.LoginRequest{Email: testUser.Email, Password: testPassword})
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := server.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}

	var session string
	cookies := res.Cookies()

	for _, cookie := range cookies {
		if cookie.Name == sessions.CookieName {
			session = cookie.Value
			break
		}
	}

	// Logout
	method = "DELETE"
	url = "/api/logout"

	req, _ = http.NewRequest(method, url, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	res, err = server.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != fiber.StatusNoContent {
		resBody, _ := io.ReadAll(res.Body)
		t.Logf("Response body: %s", resBody)
		t.Errorf("Expected status code %d, got %d", fiber.StatusNoContent, res.StatusCode)
	}

	// Check if the session was deleted
	exists := server.Config.SessionsDB.Exists(context.Background(), session)
	if exists.Err() != nil {
		t.Cleanup(func() {
			server.Config.SessionsDB.HDel(context.Background(), session)
		})
		t.Error("Expected session to be deleted")
	}
}

// TestForgottenPassword tests the forgotten password endpoint
func TestForgottenPassword(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_forgotten_password@email.com",
		Password: string(hashedPassword),
		Username: "test_forgotten_password",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	method := "POST"
	urlTemplate := "/api/forgotten-password?email=%s"
	// Test table for the forgotten password endpoint
	tests := []struct {
		name     string
		query    string
		wantCode int
	}{
		{
			name:     "Empty email",
			query:    "",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed email",
			query:    "test_forgotten_password@email",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-existent user",
			query:    "nonexistent@email.com",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Valid request",
			query:    testUser.Email,
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf(urlTemplate, tt.query)
			req, _ := http.NewRequest(method, url, nil)
			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for the forgot password token
			if res.StatusCode == fiber.StatusNoContent {
				var fp users.ForgottenPassword
				err := pgxscan.Get(context.Background(), server.Config.DB, &fp, "SELECT * FROM forgotten_passwords WHERE user_id=$1", testUser.ID)
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestResetPassword tests the reset password endpoint
func TestResetPassword(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		ID:       uuid.New(),
		Email:    "test_reset_password@email.com",
		Password: string(hashedPassword),
		Username: "test_reset_password",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	fp := users.ForgottenPassword{
		UserID: testUser.ID,
		Token:  uuid.New(),
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &fp, "INSERT INTO forgotten_passwords (user_id, token) VALUES ($1, $2) RETURNING *", fp.UserID, fp.Token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE id=$1", testUser.ID)
	})

	type ResetPasswordRequest struct {
		UserID   string `json:"user_id"`
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	method := "POST"
	url := "/api/reset-password"
	// Test table for the reset password endpoint
	tests := []struct {
		name     string
		req      ResetPasswordRequest
		wantCode int
	}{
		{
			name:     "Empty ID",
			req:      ResetPasswordRequest{UserID: "", Token: fp.Token.String(), Password: "newpassword"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-UUID ID",
			req:      ResetPasswordRequest{UserID: "1234", Token: fp.Token.String(), Password: "newpassword"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty token",
			req:      ResetPasswordRequest{UserID: fp.Token.String(), Token: "", Password: "newpassword"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-UUID token",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: "1234", Password: "newpassword"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "newpass"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "newpasswordnewpasswordnewpassword"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Invalid token for user",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: uuid.New().String(), Password: "newpassword"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Valid request",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "newpassword"},
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for the side effects
			if res.StatusCode == fiber.StatusNoContent {
				// Check if the forgotten password token was deleted
				var fp users.ForgottenPassword
				err := pgxscan.Get(context.Background(), server.Config.DB, &fp, "SELECT * FROM forgotten_passwords WHERE user_id=$1", testUser.ID)
				if err == nil {
					t.Error("Expected forgotten password token to be deleted")
				}

				// Check if the password was updated
				var user users.User
				err = pgxscan.Get(context.Background(), server.Config.DB, &user, "SELECT * FROM users WHERE id=$1", testUser.ID)
				if err != nil {
					t.Error(err)
				}

				err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.req.Password))
				if err != nil {
					t.Error("Expected password to be updated")
				}
			}
		})
	}
}
