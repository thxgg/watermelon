package users

import (
	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/internal/errors"
	"github.com/thxgg/watermelon/internal/sessions"
	"github.com/thxgg/watermelon/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct {
	Repository Repository
}

// GetSelf fetches the authenticated user
//
//	@Summary	Get the authenticated user
//	@Tags			Me
//	@Accept		json
//	@Produce	json
//	@Success	200	{object}	User
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/me [get]
//	@Security	SessionID
func (c *Controller) GetSelf(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	user, err := c.Repository.GetUser(session.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.JSON(user)
}

// UpdateSelf updates the authenticated user
//
//	@Summary	Update the authenticated user
//	@Tags			Me
//	@Accept		json
//	@Produce	json
//	@Param		request	body		UserUpdateRequest	true	"User data"
//	@Success	200		{object}	User
//	@Failure	400		{object}	errors.APIError	"Invalid request"
//	@Failure	401		{object}	errors.APIError	"Unauthorized"
//	@Failure	500		{object}	errors.APIError	"Internal server error"
//	@Router		/me [put]
//	@Security	SessionID
func (c *Controller) UpdateSelf(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	user, err := c.Repository.GetUser(session.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	var request UserUpdateRequest
	err = ctx.BodyParser(&request)
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

	user.Email = request.Email
	user.Username = request.Username

	user, err = c.Repository.UpdateUser(session.UserID, &user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(user)
}

// ChangePassword changes the authenticated user's password
//
//	@Summary	Changes the authenticated user's password
//	@Tags			Me
//	@Accept		json
//	@Produce	json
//	@Param		request	body	ChangePasswordRequest	true	"Password change data"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/me/password [put]
//	@Security	SessionID
func (c *Controller) ChangePassword(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	user, err := c.Repository.GetUser(session.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	var request ChangePasswordRequest
	err = ctx.BodyParser(&request)
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

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.OldPassword)) != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Incorrect password",
		})
	}

	newPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user.Password = string(newPassword)
	user, err = c.Repository.UpdateUser(session.UserID, &user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// DeleteSelf deletes the authenticated user
//
//	@Summary	Delete the authenticated user
//	@Tags			Me
//	@Accept		json
//	@Produce	json
//	@Success	204
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/me [delete]
//	@Security	SessionID
func (c *Controller) DeleteSelf(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	err := c.Repository.DeleteUser(session.UserID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// GetUsers fetches all existing users
//
//	@Summary	Get all existing users
//	@Tags			User
//	@Accept		json
//	@Produce	json
//	@Success	200	{array}		User
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/users [get]
//	@Security	SessionID
func (c *Controller) GetUsers(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	if !session.IsAdmin {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Unauthorized",
		})
	}

	users, err := c.Repository.GetUsers()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.JSON(users)
}

// GetUser fetches a user by given ID
//
//	@Summary	Get user
//	@Tags			User
//	@Accept		json
//	@Produce	json
//	@Param		id	path		string	true	"User ID"
//	@Success	200	{object}	User
//	@Failure	400	{object}	errors.APIError	"Bad request"
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	404	{object}	errors.APIError	"Not found"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/users/{id} [get]
//	@Security	SessionID
func (c *Controller) GetUser(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	if !session.IsAdmin {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Unauthorized",
		})
	}

	id, err := uuid.Parse(ctx.Params("id"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user, err := c.Repository.GetUser(id)
	if err != nil {
		if pgxscan.NotFound(err) {
			return ctx.Status(fiber.StatusNotFound).JSON(errors.APIError{
				Error: "User not found",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.JSON(user)
}

// UpdateUser updates a user by given ID
//
//	@Summary	Update user
//	@Tags			User
//	@Accept		json
//	@Produce	json
//	@Param		id		path		string				true	"User ID"
//	@Param		request	body		UserUpdateRequest	true	"User data"
//	@Success	200		{object}	User
//	@Failure	400		{object}	errors.APIError	"Invalid request"
//	@Failure	401		{object}	errors.APIError	"Unauthorized"
//	@Failure	404		{object}	errors.APIError	"Not found"
//	@Failure	500		{object}	errors.APIError	"Internal server error"
//	@Router		/users/{id} [put]
//	@Security	SessionID
func (c *Controller) UpdateUser(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	if !session.IsAdmin {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Unauthorized",
		})
	}

	id, err := uuid.Parse(ctx.Params("id"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	user, err := c.Repository.GetUser(id)
	if err != nil {
		if pgxscan.NotFound(err) {
			return ctx.Status(fiber.StatusNotFound).JSON(errors.APIError{
				Error: "User not found",
			})
		}

		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	var request UserUpdateRequest
	err = ctx.BodyParser(&request)
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

	user.Email = request.Email
	user.Username = request.Username

	user, err = c.Repository.UpdateUser(id, &user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(user)
}

// DeleteUser deletes a user by given ID
//
//	@Summary	Delete user
//	@Tags			User
//	@Accept		json
//	@Produce	json
//	@Param		id	path	string	true	"User ID"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Invalid request"
//	@Failure	401	{object}	errors.APIError	"Unauthorized"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/users/{id} [delete]
//	@Security	SessionID
func (c *Controller) DeleteUser(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessions.ContextEntry).(sessions.Session)

	if !session.IsAdmin {
		return ctx.Status(fiber.StatusUnauthorized).JSON(errors.APIError{
			Error: "Unauthorized",
		})
	}

	id, err := uuid.Parse(ctx.Params("id"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	err = c.Repository.DeleteUser(id)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}

// VerifyUserEmail attempts to verify a user's email given a token
//
//	@Summary	Verify a user
//	@Tags			User
//	@Accept		json
//	@Produce	json
//	@Param		id		query	string	true	"User ID"
//	@Param		token	query	string	true	"Verification token"
//	@Success	204
//	@Failure	400	{object}	errors.APIError	"Bad request"
//	@Failure	500	{object}	errors.APIError	"Internal server error"
//	@Router		/users/{id}/verify [put]
func (c *Controller) VerifyUserEmail(ctx *fiber.Ctx) error {
	id, err := uuid.Parse(ctx.Query("id"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	token, err := uuid.Parse(ctx.Query("token"))
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	isValid, err := c.Repository.IsEmailVerificationTokenValidForUser(token, id)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	if !isValid {
		return ctx.Status(fiber.StatusBadRequest).JSON(errors.APIError{
			Error: "Invalid token",
		})
	}

	err = c.Repository.VerifyUser(id)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(errors.APIError{
			Error: err.Error(),
		})
	}

	return ctx.SendStatus(fiber.StatusNoContent)
}
