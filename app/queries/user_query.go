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

	err := pgxscan.Get(context.Background(), q, &user, "UPDATE users SET email=$2, password=$3, username=$4, is_admin=$5, updated_at=NOW() WHERE id=$1 RETURNING *", u.ID, u.Email, u.Password, u.Username, u.IsAdmin)

	return user, err
}

func (q *UserQueries) DeleteUser(id uuid.UUID) error {
	_, err := q.Exec(context.Background(), "DELETE FROM users WHERE id=$1", id)

	return err
}

func (q *UserQueries) IsEmailVerificationTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), q, &res, "SELECT EXISTS (SELECT TRUE FROM user_email_verifications WHERE token=$1 AND user_id=$2)", token, id)

	return res.Exists, err
}

func (q *UserQueries) CreateUserEmailVerification(uev *models.UserEmailVerification) (models.UserEmailVerification, error) {
	var user models.UserEmailVerification

	err := pgxscan.Get(context.Background(), q, &user, "INSERT INTO user_email_verifications (user_id, token) VALUES ($1, $2) RETURNING *", uev.UserID, uev.Token)

	return user, err
}

func (q *UserQueries) VerifyUser(id uuid.UUID) error {
	_, err := q.Exec(context.Background(), "DELETE FROM user_email_verifications WHERE user_id=$1", id)
	if err != nil {
		return err
	}

	_, err = q.Exec(context.Background(), "UPDATE users SET is_verified=TRUE WHERE id=$1", id)

	return err
}

func (q *UserQueries) IsForgottenPasswordTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), q, &res, "SELECT EXISTS (SELECT TRUE FROM forgotten_passwords WHERE token=$1 AND user_id=$2 AND expires_at > NOW())", token, id)

	return res.Exists, err
}

func (q *UserQueries) CreateForgottenPassword(fp *models.ForgottenPassword) (models.ForgottenPassword, error) {
	var forgottenPassword models.ForgottenPassword

	err := pgxscan.Get(context.Background(), q, &forgottenPassword, "INSERT INTO forgotten_passwords (user_id, token) VALUES ($1, $2) RETURNING *", fp.UserID, fp.Token)

	return forgottenPassword, err
}

func (q *UserQueries) ResetPassword(id uuid.UUID, password string) error {
	_, err := q.Exec(context.Background(), "DELETE FROM forgotten_passwords WHERE user_id=$1", id)
	if err != nil {
		return err
	}

	_, err = q.Exec(context.Background(), "UPDATE users SET password=$2 WHERE id=$1", id, password)

	return err
}
