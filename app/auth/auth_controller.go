package auth

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/thxgg/watermelon/app/users"
	"github.com/thxgg/watermelon/config"
	"github.com/thxgg/watermelon/internal/email"
	"github.com/thxgg/watermelon/internal/errors"
	"github.com/thxgg/watermelon/internal/sessions"
	"github.com/thxgg/watermelon/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct {
	Config      *config.Global
	Repository  users.Repository
	SessionsDB  *redis.Client
	EmailClient *email.Client
}

// Register creates a new user
//
//	@Summary	Create a new user
//	@Tags			Auth
//	@Accept		json
//	@Produce	json
//	@Param		request	body	RegisterRequest	true	"Registration data"
//	@Success	201
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/register [post]
func (c *Controller) Register(ctx *fiber.Ctx) error {
	var request RegisterRequest
	err := ctx.BodyParser(&request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = validator.New().Struct(request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user, err := c.Repository.CreateUser(&users.User{
		Email:    request.Email,
		Password: string(hashedPassword),
		Username: request.Username,
	})
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	uev, err := c.Repository.CreateUserEmailVerification(&users.UserEmailVerification{
		UserID: user.ID,
		Token:  uuid.New(),
	})
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = c.EmailClient.SendEmailVerificationEmail(&user, uev, c.Config.Email.From)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = c.createSession(ctx, &user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusCreated)
}

// Login creates a new session for the user
//
//	@Summary	Create a new session for the user
//	@Tags			Auth
//	@Accept		json
//	@Produce	json
//	@Param		request	body	LoginRequest	true	"Login data"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	401	{object}	errors.APIError	"Invalid credentials"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/login [post]
func (c *Controller) Login(ctx *fiber.Ctx) error {
	var request LoginRequest
	err := ctx.BodyParser(&request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = validator.New().Struct(request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user, err := c.Repository.GetUserByEmail(request.Email)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Invalid credentials",
		})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Invalid credentials",
		})
	}

	err = c.createSession(ctx, &user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// Logout invalidates the user's session
//
//	@Summary	Invalidate the user's session
//	@Tags			Auth
//	@Accept		json
//	@Produce	json
//	@Success	204
//	@Router		/logout [delete]
//	@Security	SessionID
func (c *Controller) Logout(ctx *fiber.Ctx) error {
	sessionID := ctx.Cookies(sessions.CookieName)

	c.SessionsDB.Del(context.Background(), sessionID)
	// ctx.ClearCookie("sessionID") seems to be broken, this is a workaround that mimics the internals of ClearCookie
	ctx.Cookie(&fiber.Cookie{
		Name:     sessions.CookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		HTTPOnly: true,
	})

	return ctx.SendStatus(fiber.StatusNoContent)
}

// ForgottenPassword creates a forgotten password token for a user
//
//	@Summary	Create a forgotten password token for a user
//	@Tags			Auth
//	@Accept		json
//	@Produce	json
//	@Param		email	query	string	true	"User's email address"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/forgotten-password [post]
func (c *Controller) ForgottenPassword(ctx *fiber.Ctx) error {
	userEmail := ctx.Query("email")
	err := validator.New().Var(userEmail, "required,email")
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user, err := c.Repository.GetUserByEmail(userEmail)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	fp, err := c.Repository.CreateForgottenPassword(&users.ForgottenPassword{
		UserID: user.ID,
		Token:  uuid.New(),
	})
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = c.EmailClient.SendForgottenPasswordEmail(&user, fp, c.Config.BaseURL)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// ResetPassword creates a forgotten password token for a user
//
//	@Summary	Create a forgotten password token for a user
//	@Tags			Auth
//	@Accept		json
//	@Produce	json
//	@Param		request	body	ResetPasswordRequest	true	"Reset password data"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	401	{object}	errors.APIError	"Invalid token"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/reset-password [post]
func (c *Controller) ResetPassword(ctx *fiber.Ctx) error {
	var request ResetPasswordRequest
	err := ctx.BodyParser(&request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = validator.New().Struct(request)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	isValid, err := c.Repository.IsForgottenPasswordTokenValidForUser(request.Token, request.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	if !isValid {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Invalid token",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = c.Repository.ResetPassword(request.UserID, string(hashedPassword))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// createSession creates a new session for the user and sets a cookie
func (c *Controller) createSession(ctx *fiber.Ctx, user *users.User) error {
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(c.Config.Session.Duration)
	session := sessions.Session{
		UserID:       user.ID,
		UserIDString: user.ID.String(),
		IsAdmin:      user.IsAdmin,
	}

	setRes := c.SessionsDB.HSet(context.Background(), sessionID, session)
	if setRes.Err() != nil {
		log.Errorf("Error setting session details for user '%s': %s", user.ID, setRes.Err())
		return setRes.Err()
	}

	expireRes := c.SessionsDB.ExpireAt(context.Background(), sessionID, expiresAt)
	if expireRes.Err() != nil {
		log.Errorf("Error setting session expiration for user '%s': %s", user.ID, expireRes.Err())
		return expireRes.Err()
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     sessions.CookieName,
		Value:    sessionID,
		Expires:  expiresAt,
		Secure:   true,
		HTTPOnly: true,
	})
	return nil
}
