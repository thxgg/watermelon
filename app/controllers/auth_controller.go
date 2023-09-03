package controllers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/app/models"
	"github.com/thxgg/watermelon/app/queries"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/utils"
	"github.com/thxgg/watermelon/internal/validator"
	"github.com/thxgg/watermelon/platform/database"
	"golang.org/x/crypto/bcrypt"
)

// createSession creates a new session for the user
func createSession(user *models.User) (string, error) {
	expireAt := time.Now().Add(time.Hour * time.Duration(config.Config.JWT.Lifetime))
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"is_admin": user.IsAdmin,
		"exp":      expireAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(config.Config.JWT.Secret))
	if err != nil {
		return "", err
	}

	middleware.JWT_DB.SetArgs(context.Background(), signedToken, true, redis.SetArgs{
		ExpireAt: expireAt,
	})

	return signedToken, nil
}

// Session represents a user's session token
type Session struct {
	Token string `json:"token"`
}

// RegisterRequest represents the data needed to register a new user
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=32"`
	Username string `json:"username" validate:"required,min=3,max=32"`
}

// Register creates a new user
//
// @Description	Create a new user
// @Tags				Auth
// @Accept			json
// @Produce			json
// @Param 			request body RegisterRequest true "Registration data"
// @Success			201 {object} Session
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/register [post]
func Register(c *fiber.Ctx) error {
	var request RegisterRequest
	err := c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}
	err = validator.Validator.Struct(request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.CreateUser(&models.User{
		Email:    request.Email,
		Password: string(hashedPassword),
		Username: request.Username,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	uev, err := db.CreateUserEmailVerification(&models.UserEmailVerification{
		UserID: user.ID,
		Token:  uuid.New(),
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	err = utils.SendEmailVerificationEmail(&user, uev)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	token, err := createSession(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(Session{Token: token})
}

// LoginRequest represents the data needed to login a user
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=32"`
}

// Login creates a new session for the user
//
// @Description	Create a new session for the user
// @Tags				Auth
// @Accept			json
// @Produce			json
// @Param 			request body LoginRequest true "Login data"
// @Success			200 {object} Session
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     401 {object} utils.APIError "Invalid credentials"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/login [post]
func Login(c *fiber.Ctx) error {
	var request LoginRequest
	err := c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}
	err = validator.Validator.Struct(request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUserByEmail(request.Email)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": true,
			"msg":   "Invalid credentials",
		})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": true,
			"msg":   "Invalid credentials",
		})
	}

	token, err := createSession(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"token": token,
	})
}

// Logout invalidates the user's session
//
// @Description	Invalidate the user's session
// @Tags				Auth
// @Accept			json
// @Produce			json
// @Success			204
// @Failure     401 {object} utils.APIError "Invalid credentials"
// @Router			/api/logout [delete]
// @Security    Bearer
func Logout(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	_, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	middleware.JWT_DB.Del(context.Background(), token.Raw)

	return c.SendStatus(fiber.StatusNoContent)
}

// ForgottenPassword creates a forgotten password token for a user
//
// @Description Create a forgotten password token for a user
// @Tags				Auth
// @Accept			json
// @Produce			json
// @Param 			email query string true "User's email address"
// @Success			204
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/forgotten-password [post]
func ForgottenPassword(c *fiber.Ctx) error {
	email := c.Query("email")
	err := validator.Validator.Var(email, "required,email")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUserByEmail(email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	fp, err := db.CreateForgottenPassword(&models.ForgottenPassword{
		UserID: user.ID,
		Token:  uuid.New(),
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	err = utils.SendForgottenPasswordEmail(&user, fp)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ResetPasswordRequest represents the data needed to reset a user's password
type ResetPasswordRequest struct {
	ID       uuid.UUID `json:"id" validate:"required,uuid4"`
	Token    uuid.UUID `json:"token" validate:"required,uuid4"`
	Password string    `json:"password" validate:"required,min=8,max=32"`
}

// ResetPassword creates a forgotten password token for a user
//
// @Description Create a forgotten password token for a user
// @Tags				Auth
// @Accept			json
// @Produce			json
// @Param 			request body ResetPasswordRequest true "Reset password data"
// @Success			204
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/reset-password [post]
func ResetPassword(c *fiber.Ctx) error {
	var request ResetPasswordRequest
	err := c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	err = validator.Validator.Struct(request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	isValid, err := db.IsForgottenPasswordTokenValidForUser(request.Token, request.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if !isValid {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   "Invalid token",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	err = db.ResetPassword(request.ID, string(hashedPassword))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}
