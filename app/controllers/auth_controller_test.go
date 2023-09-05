package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/controllers"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/routes"
	"github.com/thxgg/watermelon/platform/database"
)

func init() {
	// Change working directory to the root of the project
	os.Chdir("../..")
	// Disable logging
	log.SetOutput(io.Discard)
}

// setup is run before each test function and sets up the test environment
func setup(t *testing.T) *fiber.App {
	// Setup config
	config.Setup()

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
	t.Cleanup(func() {
		database.DB.Close()
	})

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
				t.Logf("Request body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for the session cookie
			if res.StatusCode == fiber.StatusCreated {
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
