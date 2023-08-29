package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/app/queries"
	"github.com/thxgg/watermelon/platform/database"
)

//	GetUsers func gets all existing users
//
// @Description	Get all existing users
// @Summary		get all existing users
// @Tags			User
// @Accept			json
// @Produce		json
//
// @Success		200	{array}	models.User
// @Router			/users [get]
func GetUsers(c *fiber.Ctx) error {
	db := &queries.UserQueries{Pool: database.DB}
	users, err := db.GetUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"msg":   err.Error(),
		})
	}

	return c.JSON(users)
}

//	GetUser func gets user by given ID or 404 error
//
// @Description	Get user by given ID
// @Summary		get user by given ID
// @Tags			User
// @Accept			json
// @Produce		json
//
// @Param			id	path	string	true	"User ID"
//
// @Success		200	{object}	models.User
// @Router			/users/{id} [get]
func GetUser(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": true,
			"msg":   err.Error(),
		})
	}

	db := &queries.UserQueries{Pool: database.DB}
	user, err := db.GetUser(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": true,
			"msg":   err.Error(),
		})
	}

	return c.JSON(user)
}
