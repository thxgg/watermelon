package utils

import (
	"fmt"
	"html/template"
	"time"

	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/models"
	"github.com/thxgg/watermelon/config"
	"github.com/wneessen/go-mail"
)

var emailClient *mail.Client

func init() {
	client, err := mail.NewClient(config.Config.Email.Host, mail.WithPort(config.Config.Email.Port), mail.WithSSL(), mail.WithSMTPAuth(mail.SMTPAuthLogin), mail.WithUsername(config.Config.Email.Username), mail.WithPassword(config.Config.Email.Password))
	if err != nil {
		panic(err)
	}

	emailClient = client
}

func SendEmail(to string, subject string, templateName string, body interface{}) error {
	m := mail.NewMsg()
	if err := m.From(config.Config.Email.From); err != nil {
		log.Fatalf("Failed to set From address: %s", err)
	}
	if err := m.To(to); err != nil {
		log.Fatalf("Failed to set To address: %s", err)
	}
	m.Subject(subject)
	tmpl, err := template.ParseFiles(templateName)
	if err != nil {
		return err
	}
	m.SetBodyHTMLTemplate(tmpl, body)

	err = emailClient.DialAndSend(m)
	if err != nil {
		return err
	}

	return nil
}

func SendEmailVerificationEmail(user *models.User, uev models.UserEmailVerification) error {
	data := struct {
		Username string
		Link     string
	}{
		Username: user.Username,
		Link:     fmt.Sprintf("%s/verify?id=%s&token=%s", config.Config.BaseURL, user.ID, uev.Token),
	}

	err := SendEmail(user.Email, "Verify your email address", "templates/email_verification.html", data)
	if err != nil {
		return err
	}

	return nil
}

func SendForgottenPasswordEmail(user *models.User, fp models.ForgottenPassword) error {
	data := struct {
		Username  string
		Link      string
		ExpiresAt time.Time
	}{
		Username:  user.Username,
		Link:      fmt.Sprintf("%s/reset-password?id=%s&token=%s", config.Config.BaseURL, user.ID, fp.Token),
		ExpiresAt: fp.ExpiresAt,
	}

	err := SendEmail(user.Email, "Forgotten password", "templates/forgotten_password.html", data)
	if err != nil {
		return err
	}

	return nil
}
