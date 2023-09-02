package queries

import (
	"context"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thxgg/watermelon/app/models"
)

type UserQueries struct {
	*pgxpool.Pool
}

func (q *UserQueries) GetUsers() ([]models.User, error) {
	var users []models.User

	err := pgxscan.Select(context.Background(), q, &users, "SELECT * FROM users")

	return users, err
}

func (q *UserQueries) GetUser(id uuid.UUID) (models.User, error) {
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "SELECT * FROM users WHERE id=$1", id)

	return user, err
}

func (q *UserQueries) GetUserByEmail(email string) (models.User, error) {
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "SELECT * FROM users WHERE email=$1", email)

	return user, err
}

func (q *UserQueries) CreateUser(u *models.User) (models.User, error) {
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", u.Email, u.Password, u.Username)

	return user, err
}

func (q *UserQueries) UpdateUser(id uuid.UUID, u *models.User) (models.User, error) {
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "UPDATE users SET email=$2, password=$3, username=$4, is_admin=$5, verified=$6, updated_at=NOW() WHERE id=$1 RETURNING *", u.ID, u.Email, u.Password, u.Username, u.IsAdmin, u.Verified)

	return user, err
}

func (q *UserQueries) DeleteUser(id uuid.UUID) error {
	_, err := q.Exec(context.Background(), "DELETE FROM users WHERE id=$1", id)

	return err
}
