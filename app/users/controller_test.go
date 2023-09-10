package users_test

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
	"github.com/thxgg/watermelon/app/auth"
	"github.com/thxgg/watermelon/app/users"
	"github.com/thxgg/watermelon/internal/sessions"
	test "github.com/thxgg/watermelon/internal/testutils"
	"golang.org/x/crypto/bcrypt"
)

// TestGetSelf tests the authenticated user profile endpoint
func TestGetSelf(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_get_self@email.com",
		Password: string(hashedPassword),
		Username: "test_get_self",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
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

				body, _ := json.Marshal(auth.LoginRequest{Email: testUser.Email, Password: testPassword})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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
				var user users.User
				// Bind user to the response body
				if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
					t.Fatal(err)
				}

				// Compare the response body with the testUser
				testUser.Password = ""
				if user != testUser {
					t.Errorf("Expected user %+v to match testUser %+v on email and username.", user, testUser)
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
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:      "test_update_self@email.com",
		Password:   string(hashedPassword),
		Username:   "test_update_self",
		IsVerified: false,
	}
	testUser2 := users.User{
		Email:      "test_update_self2@email.com",
		Password:   string(hashedPassword),
		Username:   "test_update_self2",
		IsVerified: true,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser.Email, testUser.Password, testUser.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &testUser2, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser2.Email, testUser2.Password, testUser2.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser2.Email)
	})

	// Test table for the authenticated user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		req             users.UserUpdateRequest
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: testUser.Username},
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Empty email",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: "", Username: testUser.Username},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Malformed email",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: "test_update_self@email", Username: testUser.Username},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty username",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: ""},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short username",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: "us"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long username",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: "usernameusernameusernameusernameu"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Email already exists",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser2.Email, Username: testUser.Username},
			wantCode:        fiber.StatusInternalServerError,
		},
		{
			name:            "Username already exists",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: testUser2.Username},
			wantCode:        fiber.StatusInternalServerError,
		},
		{
			name:            "Update only username",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: testUser.Email, Username: "test_update_self3"},
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update both email and username",
			isAuthenticated: true,
			req:             users.UserUpdateRequest{Email: "test_update_self3@email.com", Username: "test_update_self3"},
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

				body, _ := json.Marshal(auth.LoginRequest{Email: testUser.Email, Password: testPassword})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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
				var resUser users.User
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
				var dbUser users.User
				err := pgxscan.Get(context.Background(), server.Config.DB, &dbUser, "SELECT * FROM users WHERE email=$1", tt.req.Email)
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
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_change_password@email.com",
		Password: string(hashedPassword),
		Username: "test_change_password",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
	})

	// Test table for the authenticated user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		req             users.ChangePasswordRequest
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpassword"},
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Empty old password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: "", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short old password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: "passwor", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long old password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: "passwordpasswordpasswordpasswordp", NewPassword: "newpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty new password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: ""},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short new password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpass"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long new password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpasswordnewpasswordnewpassword"},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "New password same as old password",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: testPassword},
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Valid request",
			isAuthenticated: true,
			req:             users.ChangePasswordRequest{OldPassword: testPassword, NewPassword: "newpassword"},
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

				body, _ := json.Marshal(auth.LoginRequest{Email: testUser.Email, Password: testPassword})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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
				var user users.User
				err := pgxscan.Get(context.Background(), server.Config.DB, &user, "SELECT * FROM users WHERE email=$1", testUser.Email)
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
	server := test.SetupTest(t)

	// Prepare the database data
	testPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	testUser := users.User{
		Email:    "test_delete_self@email.com",
		Password: string(hashedPassword),
		Username: "test_delete_self",
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", testUser.Email, testUser.Password, testUser.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
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

				body, _ := json.Marshal(auth.LoginRequest{Email: testUser.Email, Password: testPassword})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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

				err := pgxscan.Get(context.Background(), server.Config.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM users WHERE id=$1)", testUser.ID)
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
	server := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := users.User{
		Email:    "test_get_users_admin@email.com",
		Password: string(hashedPassword),
		Username: "test_get_users_admin",
		IsAdmin:  true,
	}
	normalUser := users.User{
		Email:    "test_get_users_normal@email.com",
		Password: string(hashedPassword),
		Username: "test_get_users_normal",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the users list endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		wantResult      []users.User
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
			wantResult:      []users.User{adminUser, normalUser},
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

				var user users.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(auth.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantResult != nil {
				// Read the response body into a slice of users.User
				resUsers := make([]users.User, 0)
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
				sortUsersByID := func(slice []users.User) func(i, j int) bool {
					return func(i, j int) bool {
						return slice[i].ID.String() < slice[j].ID.String()
					}
				}
				sort.Slice(resUsers, sortUsersByID(resUsers))
				sort.Slice(tt.wantResult, sortUsersByID(tt.wantResult))
				if reflect.DeepEqual(resUsers, tt.wantResult) {
					t.Errorf("Expected %+v but got %+v", tt.wantResult, resUsers)
				}
			}
		})
	}
}

// TestGetUser tests the user profile endpoint
func TestGetUser(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := users.User{
		Email:    "test_get_user_admin@email.com",
		Password: string(hashedPassword),
		Username: "test_get_user_admin",
		IsAdmin:  true,
	}
	normalUser := users.User{
		Email:    "test_get_user_normal@email.com",
		Password: string(hashedPassword),
		Username: "test_get_user_normal",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the user profile endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		id              string
		wantResult      *users.User
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

				var user users.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(auth.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.wantCode {
				resBody, _ := io.ReadAll(res.Body)
				t.Logf("Response body: %s", resBody)
				t.Errorf("Expected status code %d, got %d", tt.wantCode, res.StatusCode)
			}

			if tt.wantResult != nil {
				var resUser users.User
				if err := json.NewDecoder(res.Body).Decode(&resUser); err != nil {
					t.Fatal(err)
				}

				if resUser.Password != "" {
					t.Errorf("Expected password to be empty, got %s", resUser.Password)
				}

				tt.wantResult.Password = ""
				if resUser != *tt.wantResult {
					t.Errorf("Expected %+v but got %+v", tt.wantResult, resUser)
				}
			}
		})
	}
}

// TestUpdateUser tests the user profile update endpoint
func TestUpdateUser(t *testing.T) {
	server := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := users.User{
		Email:    "test_update_user_admin@email.com",
		Password: string(hashedPassword),
		Username: "test_update_user_admin",
		IsAdmin:  true,
	}
	normalUser := users.User{
		Email:      "test_update_user_normal@email.com",
		Password:   string(hashedPassword),
		Username:   "test_update_user_normal",
		IsAdmin:    false,
		IsVerified: true,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
	})

	// Test table for the user profile update endpoint
	tests := []struct {
		name            string
		isAuthenticated bool
		isAdmin         bool
		id              string
		req             users.UserUpdateRequest
		wantResult      *users.User
		wantCode        int
	}{
		{
			name:            "Unauthenticated",
			isAuthenticated: false,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Non-admin",
			isAuthenticated: true,
			isAdmin:         false,
			id:              adminUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusUnauthorized,
		},
		{
			name:            "Malformed ID",
			isAuthenticated: true,
			isAdmin:         true,
			id:              "1234",
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Non-existent user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              uuid.New().String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusNotFound,
		},
		{
			name:            "Empty email",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Malformed email",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email", Username: "test_update_user_admin1"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Empty username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: ""},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Short username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "up"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Long username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "updated_usernameupdated_usernameu"},
			wantResult:      nil,
			wantCode:        fiber.StatusBadRequest,
		},
		{
			name:            "Update only username",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: normalUser.Email, Username: "test_update_user_normal1"},
			wantResult:      &normalUser,
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update normal user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              normalUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_normal2@email.com", Username: "test_update_user_normal2"},
			wantResult:      &normalUser,
			wantCode:        fiber.StatusOK,
		},
		{
			name:            "Update admin user",
			isAuthenticated: true,
			isAdmin:         true,
			id:              adminUser.ID.String(),
			req:             users.UserUpdateRequest{Email: "test_update_user_admin1@email.com", Username: "test_update_user_admin1"},
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

				var user users.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(auth.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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
				var resUser users.User
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
					t.Errorf("Expected %+v but got %+v", tt.wantResult, resUser)
				}

				// Check if the database data matches the expected result
				var dbUser users.User
				err := pgxscan.Get(context.Background(), server.Config.DB, &dbUser, "SELECT * FROM users WHERE id=$1", tt.wantResult.ID)
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
	server := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	adminUser := users.User{
		Email:    "test_delete_user_admin@email.com",
		Password: string(hashedPassword),
		Username: "test_delete_user_admin",
		IsAdmin:  true,
	}
	adminUser2 := users.User{
		Email:    "test_delete_user_admin2@email.com",
		Password: string(hashedPassword),
		Username: "test_delete_user_admin2",
		IsAdmin:  true,
	}
	normalUser := users.User{
		Email:    "test_delete_user_normal@email.com",
		Password: string(hashedPassword),
		Username: "test_delete_user_normal",
		IsAdmin:  false,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &adminUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser.Email, adminUser.Password, adminUser.Username, adminUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &adminUser2, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", adminUser2.Email, adminUser2.Password, adminUser2.Username, adminUser2.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &normalUser, "INSERT INTO users (email, password, username, is_admin) VALUES ($1, $2, $3, $4) RETURNING *", normalUser.Email, normalUser.Password, normalUser.Username, normalUser.IsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", adminUser2.Email)
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", normalUser.Email)
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

				var user users.User
				if tt.isAdmin {
					user = adminUser
				} else {
					user = normalUser
				}
				body, _ := json.Marshal(auth.LoginRequest{Email: user.Email, Password: password})
				req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				res, err := server.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}

				var session string
				cookies = res.Cookies()

				for _, cookie := range cookies {
					if cookie.Name == sessions.CookieName {
						session = cookie.Value
						break
					}
				}

				t.Cleanup(func() {
					server.Config.SessionsDB.HDel(context.Background(), session)
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

			res, err := server.Test(req, -1)
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

				err = pgxscan.Get(context.Background(), server.Config.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM users WHERE id=$1)", tt.id)
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
	server := test.SetupTest(t)

	// Prepare the database data
	password := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := users.User{
		Email:      "test_verify_user_email@email.com",
		Password:   string(hashedPassword),
		Username:   "test_verify_user_email",
		IsVerified: false,
	}
	err := pgxscan.Get(context.Background(), server.Config.DB, &testUser, "INSERT INTO users (email, password, username, is_verified) VALUES ($1, $2, $3, $4) RETURNING *", testUser.Email, testUser.Password, testUser.Username, testUser.IsVerified)
	if err != nil {
		t.Fatal(err)
	}
	uev := users.UserEmailVerification{
		UserID: testUser.ID,
		Token:  uuid.New(),
	}
	err = pgxscan.Get(context.Background(), server.Config.DB, &uev, "INSERT INTO user_email_verifications (user_id, token) VALUES ($1, $2) RETURNING *", uev.UserID, uev.Token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Config.DB.Exec(context.Background(), "DELETE FROM users WHERE email=$1", testUser.Email)
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
			urlTemplate := "/api/verify?id=%s&token=%s"
			url := fmt.Sprintf(urlTemplate, tt.id, tt.token)
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

			// Check if the database data matches the expected result
			if tt.wantCode == fiber.StatusNoContent {
				// Check if email verification token was deleted
				var exists struct {
					Exists bool
				}

				err = pgxscan.Get(context.Background(), server.Config.DB, &exists, "SELECT EXISTS (SELECT TRUE FROM user_email_verifications WHERE user_id=$1)", tt.id)
				if err != nil {
					t.Fatal(err)
				}

				if exists.Exists {
					t.Error("Expected user email verification token to be deleted")
				}

				// Check if the user is verified
				var user users.User
				err = pgxscan.Get(context.Background(), server.Config.DB, &user, "SELECT * FROM users WHERE id=$1", tt.id)
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
