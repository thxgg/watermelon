package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/app/controllers"
	"github.com/thxgg/watermelon/app/models"
	test "github.com/thxgg/watermelon/internal/test_utils"
	"github.com/thxgg/watermelon/platform/database"
	"golang.org/x/crypto/bcrypt"
)

// TestGetSelf tests the authenticated user profile endpoint
func TestGetSelf(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	err := pgxscan.Get(context.Background(), database.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Test table for the authenticated user profile endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Authorized",
			isAuthenticated: true,
			wantCode:        fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
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
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "GET"
			url := "/api/me"
			req, _ := http.NewRequest(method, url, nil)

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check the returned user
			if res.StatusCode == fiber.StatusOK {
				var user models.User
				// Bind user to the response body
				if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
					t.Fatal(err)
				}

				// Compare the response body with the testUser
				testUser.Password = ""
				if user != testUser {
					t.Errorf("Expected user to match testUser's email and username.\nExpected: %+v\nGot: %+v", testUser, user)
				}

				// Check that the password is not returned
				if user.Password != "" {
					t.Errorf("Expected password to be empty, got %s", user.Password)
				}
			}
		})
	}
}

// TestUpdateSelf tests the authenticated user profile update endpoint
func TestUpdateSelf(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:      "test@email.com",
		Password:   string(hashedPassword),
		Username:   "testuser",
		IsVerified: false,
	}
	testUser2 := models.User{
		Email:      "test2@email.com",
		Password:   string(hashedPassword),
		Username:   "testuser2",
		IsVerified: true,
	}
	err := pgxscan.Get(context.Background(), database.DB, &testUser, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser.Email, testUser.Password, testUser.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &testUser2, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser2.Email, testUser2.Password, testUser2.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser2.Email)
	})

	// Test table for the authenticated user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		req             controllers.UserUpdateRequest
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: testUser.Username},
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Empty email",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: "", Username: testUser.Username},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Malformed email",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: "test@email", Username: testUser.Username},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty username",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: ""},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short username",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: "us"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long username",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: "usernameusernameusernameusernameu"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Email already exists",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser2.Email, Username: testUser.Username},
			wantCode:        fiber.StatusInternalServerError,
		},
		{
			name:            "Username already exists",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: testUser2.Username},
			wantCode:        fiber.StatusInternalServerError,
		},
		{
			name:            "Update only username",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: testUser.Email, Username: "testuser3"},
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update both email and username",
			isAuthenticated: true,
			req:             controllers.UserUpdateRequest{Email: "test3@email.com", Username: "testuser3"},
			wantCode:        fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
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
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "PUT"
			url := "/api/me"

			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check for side effects
			if res.StatusCode == fiber.StatusOK {
				wasEmailChanged := tt.req.Email != testUser.Email
				if wasEmailChanged {
					testUser.IsVerified = false
				}

				// Check the returned resUser
				var resUser models.User
				// Bind user to the response body
				if err := json.NewDecoder(res.Body).Decode(&resUser); err != nil {
					t.Fatal(err)
				}

				// Compare the response body email and username with the change data
				if resUser.Email != tt.req.Email || resUser.Username != tt.req.Username {
					t.Errorf("Expected user to match testUser's email and username, got %+v", resUser)
				}

				// Check that the password is not returned
				if resUser.Password != "" {
					t.Errorf("Expected password to be empty, got %s", resUser.Password)
				}

				if wasEmailChanged && resUser.IsVerified {
					t.Errorf("Expected user to be unverified, got %+v", resUser)
				}

				// Check that the database data is updated
				var dbUser models.User
				err := pgxscan.Get(context.Background(), database.DB, &dbUser, "SELECT * FROM users WHERE email=$1", tt.req.Email)
				if err != nil {
					t.Fatal(err)
				}

				// Compare the database data email and username with the testUser
				if dbUser.Email != tt.req.Email || dbUser.Username != tt.req.Username {
					t.Errorf("Expected user to match testUser's email and username, got %+v", dbUser)
				}

				// Check that the rest of the data is not changed
				testUser.Email = dbUser.Email
				testUser.Username = dbUser.Username
				testUser.UpdatedAt = dbUser.UpdatedAt
				if dbUser != testUser {
					t.Errorf("Expected only email, username and updated_at fields to have changed: %+v", dbUser)
				}
			}
		})
	}
}

// TestChangePassword tests the authenticated user password change endpoint
func TestChangePassword(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	err := pgxscan.Get(context.Background(), database.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Test table for the authenticated user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		req             controllers.ChangePasswordRequest
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpassword"},
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Empty old password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: "", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short old password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: "passwor", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long old password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: "passwordpasswordpasswordpasswordp", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty new password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: ""},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short new password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpass"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long new password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpasswordnewpasswordnewpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "New password same as old password",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: testPassword},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Valid request",
			isAuthenticated: true,
			req:             controllers.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpassword"},
			wantCode:        fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
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
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "PUT"
			url := "/api/me/password"

			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check the database data
			if res.StatusCode == fiber.StatusNoContent {
				var user models.User
				err := pgxscan.Get(context.Background(), database.DB, &user, "SELECT * FROM users WHERE email=$1", testUser.Email)
				if err != nil {
					t.Fatal(err)
				}

				if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.req.NewPassword)) != nil {
					t.Errorf("Expected password to be updated: %+v", user)
				}

				// Check that the rest of the data is not changed
				testUser.Password = user.Password
				testUser.UpdatedAt = user.UpdatedAt
				if user != testUser {
					t.Errorf("Expected only password and updated_at field to have changed: %+v", user)
				}
			}
		})
	}
}

// TestDeleteSelf tests the authenticated user profile deletion endpoint
func TestDeleteSelf(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := models.User{
		Email:    "test@email.com",
		Password: string(hashedPassword),
		Username: "testuser",
	}
	err := pgxscan.Get(context.Background(), database.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Test table for the authenticated user profile deletion endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Authorized",
			isAuthenticated: true,
			wantCode:        fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
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
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "DELETE"
			url := "/api/me"

			req, _ := http.NewRequest(method, url, nil)

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			// If the request was successful, check the database data
			if res.StatusCode == fiber.StatusNoContent {
				var exists struct {
					Exists bool
				}

				err := pgxscan.Get(context.Background(), database.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM users WHERE id=$1)", testUser.ID)
				if err != nil {
					t.Fatal(err)
				}

				if exists.Exists {
					t.Error("Expected user to be deleted")
				}
			}
		})
	}
}

// TestGetUsers tests the users list endpoint
func TestGetUsers(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := models.User{
		Email:    "admin@email.com",
		Password: string(hashedPassword),
		Username: "adminuser",
		IsAdmin:  true,
	}
	normalUser := models.User{
		Email:    "user@email.com",
		Password: string(hashedPassword),
		Username: "normaluser",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), database.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the users list endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		wantResult      []models.User
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			isAdmin:         false,
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Non-admin",
			isAuthenticated: true,
			isAdmin:         false,
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Valid request",
			isAuthenticated: true,
			isAdmin:         true,
			wantResult:      []models.User{adminUser, normalUser},
			wantCode:        fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
				// Login
				method := "POST"
				url := "/api/login"

				var user models.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(controllers.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "GET"
			url := "/api/users"

			req, _ := http.NewRequest(method, url, nil)

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantResult != nil {
				// Read the response body into a slice of models.User
				resUsers := make([]models.User, 0)
				if err := json.NewDecoder(res.Body).Decode(&resUsers); err != nil {
					t.Fatal(err)
				}

				for _, resUser := range resUsers {
					// Check that the password is not returned
					if resUser.Password != "" {
						t.Errorf("Expected password to be empty, got %s", resUser.Password)
					}
				}

				// Compare the response body with the testUsers via sort
				sortUsersByID := func(slice []models.User) func(i, j int) bool {
					return func(i, j int) bool {
						return slice[i].ID.String() < slice[j].ID.String()
					}
				}
				sort.Slice(resUsers, sortUsersByID(resUsers))
				sort.Slice(tt.wantResult, sortUsersByID(tt.wantResult))
				if reflect.DeepEqual(resUsers, tt.wantResult) {
					t.Errorf("Expected: %+v\nGot: %+v", tt.wantResult, resUsers)
				}
			}
		})
	}
}

// TestGetUser tests the user profile endpoint
func TestGetUser(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := models.User{
		Email:    "admin@email.com",
		Password: string(hashedPassword),
		Username: "adminuser",
		IsAdmin:  true,
	}
	normalUser := models.User{
		Email:    "user@email.com",
		Password: string(hashedPassword),
		Username: "normaluser",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), database.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the user profile endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		id              string
		wantResult      *models.User
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Non-admin",
			isAuthenticated: true,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Malformed ID",
			isAuthenticated: true,
			isAdmin:         true,
			id:              "1234",
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Non-existent user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              uuid.New().String(),
			wantResult:      nil,
			wantCode:        fiber.StatusNotFound,
		},
		{
			name:            "Get normal user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			wantResult:      &normalUser,
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Get admin user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              adminUser.ID.String(),
			wantResult:      &adminUser,
			wantCode:        fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
				// Login
				method := "POST"
				url := "/api/login"

				var user models.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(controllers.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "GET"
			urlTemplate := "/api/users/%s"
			url := fmt.Sprintf(urlTemplate, tt.id)
			req, _ := http.NewRequest(method, url, nil)

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantResult != nil {
				var resUser models.User
				if err := json.NewDecoder(res.Body).Decode(&resUser); err != nil {
					t.Fatal(err)
				}

				if resUser.Password != "" {
					t.Errorf("Expected password to be empty, got %s", resUser.Password)
				}

				tt.wantResult.Password = ""
				if resUser != *tt.wantResult {
					t.Errorf("Expected: %+v\nGot: %+v", tt.wantResult, resUser)
				}
			}
		})
	}
}

// TestUpdateUser tests the user profile update endpoint
func TestUpdateUser(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := models.User{
		Email:    "admin@email.com",
		Password: string(hashedPassword),
		Username: "adminuser",
		IsAdmin:  true,
	}
	normalUser := models.User{
		Email:      "user@email.com",
		Password:   string(hashedPassword),
		Username:   "normaluser",
		IsAdmin:    false,
		IsVerified: true,
	}
	err := pgxscan.Get(context.Background(), database.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		id              string
		req             controllers.UserUpdateRequest
		wantResult      *models.User
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Non-admin",
			isAuthenticated: true,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Malformed ID",
			isAuthenticated: true,
			isAdmin:         true,
			id:              "1234",
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Non-existent user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              uuid.New().String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusNotFound,
		},
		{
			name:            "Empty email",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Malformed email",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email", Username: "updated_username"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: ""},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "up"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated@email.com", Username: "updated_usernameupdated_usernameu"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Update only username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: normalUser.Email, Username: "updated_normal"},
			wantResult:      &normalUser,
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update normal user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated_normal@email.com", Username: "updated_normal_again"},
			wantResult:      &normalUser,
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update admin user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              adminUser.ID.String(),
			req:             controllers.UserUpdateRequest{Email: "updated_admin@email.com", Username: "updated_admin"},
			wantResult:      &adminUser,
			wantCode:        fiber.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
				// Login
				method := "POST"
				url := "/api/login"

				var user models.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(controllers.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "PUT"
			urlTemplate := "/api/users/%s"
			url := fmt.Sprintf(urlTemplate, tt.id)
			body, _ := json.Marshal(tt.req)
			req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantResult != nil {
				wasEmailChanged := tt.req.Email != tt.wantResult.Email

				// Check if the response body matches the expected result
				var resUser models.User
				if err := json.NewDecoder(res.Body).Decode(&resUser); err != nil {
					t.Fatal(err)
				}

				if resUser.Password != "" {
					t.Errorf("Expected password to be empty, got %s", resUser.Password)
				}

				tt.wantResult.Email = tt.req.Email
				tt.wantResult.Username = tt.req.Username
				tt.wantResult.Password = ""
				tt.wantResult.UpdatedAt = resUser.UpdatedAt
				if resUser != *tt.wantResult {
					t.Errorf("Expected: %+v\nGot: %+v", tt.wantResult, resUser)
				}

				// Check if the database data matches the expected result
				var dbUser models.User
				err := pgxscan.Get(context.Background(), database.DB, &dbUser, "SELECT * FROM users WHERE id=$1", tt.wantResult.ID)
				if err != nil {
					t.Fatal(err)
				}

				dbUser.Password = ""
				if wasEmailChanged {
					tt.wantResult.IsVerified = false
				}
				if dbUser != *tt.wantResult {
					t.Errorf("Expected: %+v\nGot: %+v", tt.wantResult, dbUser)
				}

				// Ensure is_verified is false if email was updated
				if wasEmailChanged && dbUser.IsVerified {
					t.Error("Expected is_verified to be false")
				}
			}
		})
	}
}

// TestDeleteUser tests the user profile deletion endpoint
func TestDeleteUser(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := models.User{
		Email:    "admin@email.com",
		Password: string(hashedPassword),
		Username: "adminuser",
		IsAdmin:  true,
	}
	adminUser2 := models.User{
		Email:    "admin2@email.com",
		Password: string(hashedPassword),
		Username: "adminuser2",
		IsAdmin:  true,
	}
	normalUser := models.User{
		Email:    "user@email.com",
		Password: string(hashedPassword),
		Username: "normaluser",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), database.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &adminUser2, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser2.Email, adminUser2.Password, adminUser2.Username, adminUser2.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), database.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser2.Email)
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the user profile delete endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		id              string
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Non-admin",
			isAuthenticated: true,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Malformed ID",
			isAuthenticated: true,
			isAdmin:         true,
			id:              "1234",
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Delete normal user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			wantCode:        fiber.StatusNoContent,
		},
		{
			name:            "Delete admin user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              adminUser2.ID.String(),
			wantCode:        fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tt.isAuthenticated {
				// Login
				method := "POST"
				url := "/api/login"

				var user models.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(controllers.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == "sessionID" {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					// Clean up
					database.SessionsDB.HDel(context.Background(), session)
				})
			}

			method := "DELETE"
			urlTemplate := "/api/users/%s"
			url := fmt.Sprintf(urlTemplate, tt.id)
			req, _ := http.NewRequest(method, url, nil)

			if tt.isAuthenticated {
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			}

			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantCode == fiber.StatusNoContent {
				// Check if the database data matches the expected result
				var exists struct {
					Exists bool
				}

				err = pgxscan.Get(context.Background(), database.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM users WHERE id=$1)", tt.id)
				if err != nil {
					t.Fatal(err)
				}

				if exists.Exists {
					t.Error("Expected user to be deleted")
				}
			}
		})
	}
}

// TestVerifyUserEmail tests the user email verification endpoint
func TestVerifyUserEmail(t *testing.T) {
	app := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := models.User{
		Email:      "test@email.com",
		Password:   string(hashedPassword),
		Username:   "testuser",
		IsVerified: false,
	}
	err := pgxscan.Get(context.Background(), database.DB, &testUser, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser.Email, testUser.Password, testUser.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	uev := models.UserEmailVerification{
		UserID: testUser.ID,
		Token:  uuid.New(),
	}
	err = pgxscan.Get(context.Background(), database.DB, &uev, "INSERT INTO user_email_verifications (user_id, token) VALUES ($1, $2) RETURNING *", uev.UserID, uev.Token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Clean up
		database.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Test table for the user email verification endpoint
	tests := []struct {
		name     string
		id       string
		token    string
		wantCode int
	}{
		{
			name:     "Malformed ID",
			id:       "1234",
			token:    uev.Token.String(),
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Missing token",
			id:       uev.UserID.String(),
			token:    "",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Malformed token",
			id:       uev.UserID.String(),
			token:    "1234",
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Invalid token for user",
			id:       uev.UserID.String(),
			token:    uuid.New().String(),
			wantCode: fiber.StatusBadRequest,
		},
		{
			name:     "Valid request",
			id:       uev.UserID.String(),
			token:    uev.Token.String(),
			wantCode: fiber.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := "PUT"
			urlTemplate := "/api/users/%s/verify?token=%s"
			url := fmt.Sprintf(urlTemplate, tt.id, tt.token)
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

			// Check if the database data matches the expected result
			if tt.wantCode == fiber.StatusNoContent {
				// Check if email verification token was deleted
				var exists struct {
					Exists bool
				}

				err = pgxscan.Get(context.Background(), database.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM user_email_verifications WHERE user_id=$1)", tt.id)
				if err != nil {
					t.Fatal(err)
				}

				if exists.Exists {
					t.Error("Expected user email verification token to be deleted")
				}

				// Check if the user is verified
				var user models.User
				err = pgxscan.Get(context.Background(), database.DB, &user, "SELECT * FROM users WHERE id=$1", tt.id)
				if err != nil {
					t.Fatal(err)
				}

				if !user.IsVerified {
					t.Error("Expected user to be verified")
				}
			}
		})
	}
}
