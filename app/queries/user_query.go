package queries

import (
	"context"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thxgg/watermelon/app/models"
)

type UserQueries struct {
	*pgxpool.Pool
}

func (q *UserQueries) GetUsers() ([]models.User, error) {
	log.Debug("Getting all users")
	var users []models.User

	err := pgxscan.Select(context.Background(), q, &users, "SELECT * FROM users")
	if err != nil {
		log.Error("Failed to get users")
	}

	return users, err
}

func (q *UserQueries) GetUser(id uuid.UUID) (models.User, error) {
	log.Debugf("Getting user with ID '%s'", id)
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "SELECT * FROM users WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to get user '%s': %s", id, err)
	}

	return user, err
}

func (q *UserQueries) GetUserByEmail(email string) (models.User, error) {
	log.Debugf("Getting user with email '%s'", email)
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "SELECT * FROM users WHERE email=$1", email)
	if err != nil {
		log.Errorf("Failed to get user by email '%s': %s", email, err)
	}

	return user, err
}

func (q *UserQueries) CreateUser(u *models.User) (models.User, error) {
	log.Debugf("Creating user with email '%s'", u.Email)
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", u.Email, u.Password, u.Username)
	if err != nil {
		log.Errorf("Failed to create user with email '%s': %s", u.Email, err)
	}

	return user, err
}

func (q *UserQueries) UpdateUser(id uuid.UUID, u *models.User) (models.User, error) {
	log.Debugf("Updating user with ID '%s'", id)
	var user models.User

	err := pgxscan.Get(context.Background(), q, &user, "UPDATE users SET email=$2, password=$3, username=$4, is_admin=$5, updated_at=NOW() WHERE id=$1 RETURNING *", u.ID, u.Email, u.Password, u.Username, u.IsAdmin)
	if err != nil {
		log.Errorf("Failed to update user '%s': %s", id, err)
	}

	return user, err
}

func (q *UserQueries) DeleteUser(id uuid.UUID) error {
	log.Debug("Deleting user")
	_, err := q.Exec(context.Background(), "DELETE FROM users WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete user '%s': %s", id, err)
	}

	return err
}

func (q *UserQueries) IsEmailVerificationTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	log.Debugf("Checking if email verification token '%s' is valid for user with ID '%s'", token, id)
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), q, &res, "SELECT EXISTS (SELECT TRUE FROM user_email_verifications WHERE token=$1 AND user_id=$2)", token, id)
	if err != nil {
		log.Errorf("Failed to check if email verification token '%s' is valid for user '%s': %s", token, id, err)
	}

	return res.Exists, err
}

func (q *UserQueries) CreateUserEmailVerification(uev *models.UserEmailVerification) (models.UserEmailVerification, error) {
	log.Debugf("Creating email verification token for user with ID '%s'", uev.UserID)
	var user models.UserEmailVerification

	err := pgxscan.Get(context.Background(), q, &user, "INSERT INTO user_email_verifications (user_id, token) VALUES ($1, $2) RETURNING *", uev.UserID, uev.Token)
	if err != nil {
		log.Errorf("Failed to create user email verification token for user '%s': %s", uev.UserID, err)
	}

	return user, err
}

func (q *UserQueries) VerifyUser(id uuid.UUID) error {
	log.Debugf("Verifying user with ID '%s'", id)
	_, err := q.Exec(context.Background(), "DELETE FROM user_email_verifications WHERE user_id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete user email verification token for user '%s': %s", id, err)
		return err
	}

	_, err = q.Exec(context.Background(), "UPDATE users SET is_verified=TRUE WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to update user '%s' verification status: %s", id, err)
	}

	return err
}

func (q *UserQueries) IsForgottenPasswordTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	log.Debugf("Checking if forgotten password token '%s' is valid for user with ID '%s'", token, id)
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), q, &res, "SELECT EXISTS (SELECT TRUE FROM forgotten_passwords WHERE token=$1 AND user_id=$2 AND expires_at > NOW())", token, id)
	if err != nil {
		log.Errorf("Failed to check if forgotten password token '%s' is valid for user '%s': %s", token, id, err)
	}

	return res.Exists, err
}

func (q *UserQueries) CreateForgottenPassword(fp *models.ForgottenPassword) (models.ForgottenPassword, error) {
	log.Debugf("Creating forgotten password token for user with ID '%s'", fp.UserID)
	var forgottenPassword models.ForgottenPassword

	err := pgxscan.Get(context.Background(), q, &forgottenPassword, "INSERT INTO forgotten_passwords (user_id, token) VALUES ($1, $2) RETURNING *", fp.UserID, fp.Token)
	if err != nil {
		log.Errorf("Failed to create forgotten password token for user '%s': %s", fp.UserID, err)
	}

	return forgottenPassword, err
}

func (q *UserQueries) ResetPassword(id uuid.UUID, password string) error {
	log.Debugf("Resetting password for user with ID '%s'", id)
	_, err := q.Exec(context.Background(), "DELETE FROM forgotten_passwords WHERE user_id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete forgotten password token for user '%s': %s", id, err)
		return err
	}

	_, err = q.Exec(context.Background(), "UPDATE users SET password=$2 WHERE id=$1", id, password)
	if err != nil {
		log.Errorf("Failed to update user '%s' password: %s", id, err)
	}

	return err
}
