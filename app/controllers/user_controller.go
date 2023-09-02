package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/app/queries"
	"github.com/thxgg/watermelon/internal/middleware"
	"github.com/thxgg/watermelon/internal/utils"
	"github.com/thxgg/watermelon/platform/database"
	"golang.org/x/crypto/bcrypt"
)

// GetSelf fetches the authenticated user
//
// @Description	Get the authenticated user
// @Tags				User
// @Accept			json
// @Produce			json
// @Success			200	{object} models.User
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/me [get]
// @Security    Bearer
func GetSelf(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	id, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUser(*id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.JSON(user)
}

// UserUpdateRequest represents the request body for updating a user
type UserUpdateRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

// UpdateSelf updates the authenticated user
//
// @Description	Update the authenticated user
// @Tags				User
// @Accept			json
// @Produce			json
// @Param 			request body UserUpdateRequest true "User data"
// @Success			200 {object} models.User
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/me [put]
// @Security    Bearer
func UpdateSelf(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	id, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUser(*id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	var request UserUpdateRequest
	err = c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	user.Email = request.Email
	user.Username = request.Username

	user, err = db.UpdateUser(*id, &user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

// ChangePasswordRequest represents the request body for changing a user's password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword changes the authenticated user's password
//
// @Description	Changes the authenticated user's password
// @Tags				User
// @Accept			json
// @Produce			json
// @Param 			request body ChangePasswordRequest true "Password change data"
// @Success			204
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/me/password [put]
// @Security    Bearer
func ChangePassword(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	id, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUser(*id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	var request ChangePasswordRequest
	err = c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.OldPassword)) != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   "invalid password",
		})
	}

	newPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}
	user.Password = string(newPassword)
	user, err = db.UpdateUser(*id, &user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteSelf deletes the authenticated user
//
// @Description	Delete the authenticated user
// @Tags				User
// @Accept			json
// @Produce			json
// @Success			204
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/me [delete]
// @Security    Bearer
func DeleteSelf(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	id, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	err = db.DeleteUser(*id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// GetUsers fetches all existing users
//
// @Description	Get all existing users
// @Tags				User
// @Accept			json
// @Produce			json
// @Success			200	{array}	models.User
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/users [get]
// @Security    Bearer
func GetUsers(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	principalId, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	principal, err := db.GetUser(*principalId)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if !principal.IsAdmin {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   "unauthorized",
		})
	}

	users, err := db.GetUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.JSON(users)
}

// GetUser fetches a user by given ID
//
// @Description	Get user by given ID
// @Tags				User
// @Accept			json
// @Produce			json
// @Param				id path string true "User ID"
// @Success			200 {object} models.User
// @Failure			400 {object} utils.APIError "Bad request"
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/users/{id} [get]
// @Security    Bearer
func GetUser(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	principalId, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	principal, err := db.GetUser(*principalId)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if !principal.IsAdmin {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   "unauthorized",
		})
	}

	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	user, err := db.GetUser(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.JSON(user)
}

// UpdateUser updates a user by given ID
//
// @Description	Update user by given ID
// @Tags				User
// @Accept			json
// @Produce			json
// @Param				id path string true "User ID"
// @Param 			request body UserUpdateRequest true "User data"
// @Success			200 {object} models.User
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/users/{id} [put]
// @Security    Bearer
func UpdateUser(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	principalId, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	principal, err := db.GetUser(*principalId)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if !principal.IsAdmin {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   "unauthorized",
		})
	}

	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	user, err := db.GetUser(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	var request UserUpdateRequest
	err = c.BodyParser(&request)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	user.Email = request.Email
	user.Username = request.Username

	user, err = db.UpdateUser(id, &user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

// DeleteUser deletes a user by given ID
//
// @Description	Delete user by given ID
// @Tags				User
// @Accept			json
// @Produce			json
// @Param				id path string true "User ID"
// @Success			204
// @Failure     400 {object} utils.APIError "Invalid request"
// @Failure     401 {object} utils.APIError "Unauthorized"
// @Failure     500 {object} utils.APIError "Internal server error"
// @Router			/api/users/{id} [delete]
// @Security    Bearer
func DeleteUser(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	principalId, err := middleware.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	principal, err := db.GetUser(*principalId)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	if !principal.IsAdmin {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.APIError{
			Error: true,
			Msg:   "unauthorized",
		})
	}

	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	err = db.DeleteUser(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(utils.APIError{
			Error: true,
			Msg:   err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}
