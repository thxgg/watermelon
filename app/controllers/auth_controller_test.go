package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/app/controllers"
	"github.com/thxgg/watermelon/app/models"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/routes"
	"github.com/thxgg/watermelon/internal/validator"
	"github.com/thxgg/watermelon/platform/database"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	// Change working directory to the root of the project
	os.Chdir("../..")
	if os.Getenv("WATERMELON_TEST_LOG") != "true" {
		// Disable logging
		log.SetOutput(io.Discard)
	}
}

// setup is run before each test function and sets up the test environment
func setup(t *testing.T) *fiber.App {
	// Setup config
	config.Setup()

	// Setup validator
	validator.Setup()

	// Connect to the database
	err := database.Connect()
	if err != nil {
		log.Fatal("Failed to connect to the database")
	}
	t.Cleanup(func() {
		database.DB.Close()
	})

	// Connect to the sessions database
	err = database.ConnectSessionsDB()
	if err != nil {
		log.Fatal("Failed to connect to the sessions database")
	}
	t.Cleanup(func() {
		database.SessionsDB.Close()
	})

	// Setup email client
	err = email.SetupEmailClient()
	if err != nil {
		log.Fatal("Failed to setup email client")
	}
	t.Cleanup(func() {
		email.CloseEmailClient()
	})

	// Configure the Fiber app
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	t.Cleanup(func() {
		app.Shutdown()
	})

	// Setup Fiber middleware
	middleware.FiberMiddleware(app)

	// Setup routes
	api := app.Group("/api")
	routes.SwaggerRoute(api)
	routes.MonitorRoute(api)
	routes.PublicRoutes(api)
	routes.PrivateRoutes(api)
	routes.NotFoundRoute(api)

	return app
}

// TestRegister tests the register endpoint
func TestRegister(t *testing.T) {
	app := setup(t)

	method := "POST"
	url := "/api/register"
	// Test table for the register endpoint
	tests := []struct {
		name     string
		req      controllers.RegisterRequest
		wantCode int
	}{
		{
			name:     "Empty email",
			req:      controllers.RegisterRequest{Email: "", Password: "password", Username: "use"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed email",
			req:      controllers.RegisterRequest{Email: "test@email", Password: "password", Username: "use"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "", Username: "use"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "passwor", Username: "use"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "passwordpasswordpasswordpasswordp", Username: "use"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty username",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "password", Username: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short username",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "password", Username: "us"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long username",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "password", Username: "usernameusernameusernameusernameu"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Valid request",
			req:      controllers.RegisterRequest{Email: "test@email.com", Password: "password", Username: "use"},
			wantCode: fiber.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantCode == fiber.StatusCreated {
				t.Cleanup(func() {
					// Clean up
					log.Infof("Cleaning up user %s", tt.req.Email)
					_, err := database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", tt.req.Email)
					if err != nil {
						t.Error(err)
					}
				})
			}

			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for the side effects
			if res.StatusCode == fiber.StatusCreated {
				// Session cookie
				cookies := res.Cookies()
				found := false

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						if !cookie.HttpOnly {
							t.Error("Expected session cookie to be HTTP only")
						}

						if !cookie.Secure {
							t.Error("Expected session cookie to be secure")
						}

						t.Cleanup(func() {
							// Clean up
							database.SessionsDB.HDel(context.Background(), cookie.Value)
						})

						found = true
						break
					}
				}

				if !found {
					t.Error("Expected a session cookie, got none")
				}

				// Email verification token
				var uev models.UserEmailVerification
				err := pgxscan.Get(context.Background(), database.DB, &uev, "SELECT uev.* FROM user_email_verifications uev JOIN users u ON uev.user_id = u.id WHERE u.email=$1", tt.req.Email)
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestLogin tests the login endpoint
func TestLogin(t *testing.T) {
	app := setup(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	database.DB.Exec(context.Background(), "INSERT INTO users (email, password, username) VALUES ($1, $2, $3)", testUser.Email, testUser.Password, testUser.Username)
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	method := "POST"
	url := "/api/login"
	// Test table for the login endpoint
	tests := []struct {
		name     string
		req      controllers.LoginRequest
		wantCode int
	}{
		{
			name:     "Empty email",
			req:      controllers.LoginRequest{Email: "", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed email",
			req:      controllers.LoginRequest{Email: "test@email", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      controllers.LoginRequest{Email: "test@email.com", Password: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      controllers.LoginRequest{Email: "test@email.com", Password: "passwor"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      controllers.LoginRequest{Email: "test@email.com", Password: "passwordpasswordpasswordpasswordp"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-existent user",
			req:      controllers.LoginRequest{Email: "nonexistant@email.com", Password: "password"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Invalid credentials",
			req:      controllers.LoginRequest{Email: "test@email.com", Password: "password1"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Valid request",
			req:      controllers.LoginRequest{Email: testUser.Email, Password: testPassword},
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := app.Test(req, -1)
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
					if cookie.Name == "sessionID" {
						if !cookie.HttpOnly {
							t.Error("Expected session cookie to be HTTP only")
						}

						if !cookie.Secure {
							t.Error("Expected session cookie to be secure")
						}

						found = true
						t.Cleanup(func() {
							// Clean up
							database.SessionsDB.HDel(context.Background(), cookie.Value)
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
	app := setup(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	database.DB.Exec(context.Background(), "INSERT INTO users (email, password, username) VALUES ($1, $2, $3)", testUser.Email, testUser.Password, testUser.Username)
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Login
	method := "POST"
	url := "/api/login"

	body, _ := json.Marshal(controllers.LoginRequest{Email: testUser.Email, Password: testPassword})
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}

	var session string
	cookies := res.Cookies()

	for _, cookie := range cookies {
		if cookie.Name == "sessionID" {
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
	res, err = app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != fiber.StatusNoContent {
		resBody, _ := io.ReadAll(res.Body)
		t.Logf("Response body: %s", resBody)
		t.Errorf("Expected status code %d, got %d", fiber.StatusNoContent, res.StatusCode)
	}

	// Check if the session was deleted
	exists := database.SessionsDB.Exists(context.Background(), session)
	if exists.Err() != nil {
		t.Cleanup(func() {
			// Clean up
			database.SessionsDB.HDel(context.Background(), session)
		})
		t.Error("Expected session to be deleted")
	}
}

// TestForgottenPassword tests the forgotten password endpoint
func TestForgottenPassword(t *testing.T) {
	app := setup(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		ID:       uuid.New(),
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	database.DB.Exec(context.Background(), "INSERT INTO users (id, email, password, username) VALUES ($1, $2, $3, $4)", testUser.ID, testUser.Email, testUser.Password, testUser.Username)
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE id=$1", testUser.ID)
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
			query:    "test@email",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-existent user",
			query:    "nonexistant@email.com",
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
			res, err := app.Test(req, -1)
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
				var fp models.ForgottenPassword
				err := pgxscan.Get(context.Background(), database.DB, &fp, "SELECT * FROM forgotten_passwords WHERE user_id=$1", testUser.ID)
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// TestResetPassword tests the reset password endpoint
func TestResetPassword(t *testing.T) {
	app := setup(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		ID:       uuid.New(),
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	database.DB.Exec(context.Background(), "INSERT INTO users (id, email, password, username) VALUES ($1, $2, $3, $4)", testUser.ID, testUser.Email, testUser.Password, testUser.Username)
	fp := models.ForgottenPassword{
		UserID: testUser.ID,
		Token:  uuid.New(),
	}
	database.DB.Exec(context.Background(), "INSERT INTO forgotten_passwords (user_id, token) VALUES ($1, $2)", fp.UserID, fp.Token)
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE id=$1", testUser.ID)
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
			req:      ResetPasswordRequest{UserID: "", Token: fp.Token.String(), Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-UUID ID",
			req:      ResetPasswordRequest{UserID: "1234", Token: fp.Token.String(), Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty token",
			req:      ResetPasswordRequest{UserID: fp.Token.String(), Token: "", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Non-UUID token",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: "1234", Password: "password"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Empty password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: ""},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Short password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "passwor"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Long password",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "passwordpasswordpasswordpasswordp"},
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Invalid token for user",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: uuid.New().String(), Password: "password"},
			wantCode: fiber.StatusUnauthorized,
		},
		{
			name:     "Valid request",
			req:      ResetPasswordRequest{UserID: fp.UserID.String(), Token: fp.Token.String(), Password: "new_password"},
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			res, err := app.Test(req, -1)
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
				var fp models.ForgottenPassword
				err := pgxscan.Get(context.Background(), database.DB, &fp, "SELECT * FROM forgotten_passwords WHERE user_id=$1", testUser.ID)
				if err == nil {
					t.Error("Expected forgotten password token to be deleted")
				}

				// Check if the password was updated
				var user models.User
				err = pgxscan.Get(context.Background(), database.DB, &user, "SELECT * FROM users WHERE id=$1", testUser.ID)
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
