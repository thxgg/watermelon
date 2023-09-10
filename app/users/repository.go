package users

import (
	"context"

	"github.com/georgysavva/scany/v2/pgxscan"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/uuid"
	"github.com/thxgg/watermelon/internal/database"
)

type Repository struct {
	database.Database
}

func (r *Repository) GetUsers() ([]User, error) {
	log.Debug("Getting all users")
	var users []User

	err := pgxscan.Select(context.Background(), r, &users, "SELECT * FROM users")
	if err != nil {
		log.Error("Failed to get users")
	}

	return users, err
}

func (r *Repository) GetUser(id uuid.UUID) (User, error) {
	log.Debugf("Getting user with ID '%s'", id)
	var user User

	err := pgxscan.Get(context.Background(), r, &user, "SELECT * FROM users WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to get user '%s': %s", id, err)
	}

	return user, err
}

func (r *Repository) GetUserByEmail(email string) (User, error) {
	log.Debugf("Getting user with email '%s'", email)
	var user User

	err := pgxscan.Get(context.Background(), r, &user, "SELECT * FROM users WHERE email=$1", email)
	if err != nil {
		log.Errorf("Failed to get user by email '%s': %s", email, err)
	}

	return user, err
}

func (r *Repository) CreateUser(u *User) (User, error) {
	log.Debugf("Creating user with email '%s'", u.Email)
	var user User

	err := pgxscan.Get(context.Background(), r, &user, "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *", u.Email, u.Password, u.Username)
	if err != nil {
		log.Errorf("Failed to create user with email '%s': %s", u.Email, err)
	}

	return user, err
}

func (r *Repository) UpdateUser(id uuid.UUID, u *User) (User, error) {
	log.Debugf("Updating user with ID '%s'", id)
	var user User

	err := pgxscan.Get(context.Background(), r, &user, "UPDATE users SET email=$2, password=$3, username=$4, is_admin=$5, updated_at=NOW() WHERE id=$1 RETURNING *", u.ID, u.Email, u.Password, u.Username, u.IsAdmin)
	if err != nil {
		log.Errorf("Failed to update user '%s': %s", id, err)
	}

	return user, err
}

func (r *Repository) DeleteUser(id uuid.UUID) error {
	log.Debug("Deleting user")
	_, err := r.Exec(context.Background(), "DELETE FROM users WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete user '%s': %s", id, err)
	}

	return err
}

func (r *Repository) IsEmailVerificationTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	log.Debugf("Checking if email verification token '%s' is valid for user with ID '%s'", token, id)
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), r, &res, "SELECT EXISTS (SELECT TRUE FROM user_email_verifications WHERE token=$1 AND user_id=$2)", token, id)
	if err != nil {
		log.Errorf("Failed to check if email verification token '%s' is valid for user '%s': %s", token, id, err)
	}

	return res.Exists, err
}

func (r *Repository) CreateUserEmailVerification(uev *UserEmailVerification) (UserEmailVerification, error) {
	log.Debugf("Creating email verification token for user with ID '%s'", uev.UserID)
	var user UserEmailVerification

	err := pgxscan.Get(context.Background(), r, &user, "INSERT INTO user_email_verifications (user_id, token) VALUES ($1, $2) RETURNING *", uev.UserID, uev.Token)
	if err != nil {
		log.Errorf("Failed to create user email verification token for user '%s': %s", uev.UserID, err)
	}

	return user, err
}

func (r *Repository) VerifyUser(id uuid.UUID) error {
	log.Debugf("Verifying user with ID '%s'", id)
	_, err := r.Exec(context.Background(), "DELETE FROM user_email_verifications WHERE user_id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete user email verification token for user '%s': %s", id, err)
		return err
	}

	_, err = r.Exec(context.Background(), "UPDATE users SET is_verified=TRUE WHERE id=$1", id)
	if err != nil {
		log.Errorf("Failed to update user '%s' verification status: %s", id, err)
	}

	return err
}

func (r *Repository) IsForgottenPasswordTokenValidForUser(token uuid.UUID, id uuid.UUID) (bool, error) {
	log.Debugf("Checking if forgotten password token '%s' is valid for user with ID '%s'", token, id)
	var res struct {
		Exists bool
	}

	err := pgxscan.Get(context.Background(), r, &res, "SELECT EXISTS (SELECT TRUE FROM forgotten_passwords WHERE token=$1 AND user_id=$2 AND expires_at > NOW())", token, id)
	if err != nil {
		log.Errorf("Failed to check if forgotten password token '%s' is valid for user '%s': %s", token, id, err)
	}

	return res.Exists, err
}

func (r *Repository) CreateForgottenPassword(fp *ForgottenPassword) (ForgottenPassword, error) {
	log.Debugf("Creating forgotten password token for user with ID '%s'", fp.UserID)
	var forgottenPassword ForgottenPassword

	err := pgxscan.Get(context.Background(), r, &forgottenPassword, "INSERT INTO forgotten_passwords (user_id, token) VALUES ($1, $2) RETURNING *", fp.UserID, fp.Token)
	if err != nil {
		log.Errorf("Failed to create forgotten password token for user '%s': %s", fp.UserID, err)
	}

	return forgottenPassword, err
}

func (r *Repository) ResetPassword(id uuid.UUID, password string) error {
	log.Debugf("Resetting password for user with ID '%s'", id)
	_, err := r.Exec(context.Background(), "DELETE FROM forgotten_passwords WHERE user_id=$1", id)
	if err != nil {
		log.Errorf("Failed to delete forgotten password token for user '%s': %s", id, err)
		return err
	}

	_, err = r.Exec(context.Background(), "UPDATE users SET password=$2 WHERE id=$1", id, password)
	if err != nil {
		log.Errorf("Failed to update user '%s' password: %s", id, err)
	}

	return err
}
