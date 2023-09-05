package email

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

func SetupEmailClient() error {
	log.Debug("Setting up email client")
	clientOptions := []mail.Option{mail.WithPort(config.Config.Email.Port), mail.WithSMTPAuth(mail.SMTPAuthLogin), mail.WithUsername(config.Config.Email.Username), mail.WithPassword(config.Config.Email.Password)}
	if config.Config.Email.SSL {
		clientOptions = append(clientOptions, mail.WithSSL())
	}
	client, err := mail.NewClient(config.Config.Email.Host, clientOptions...)
	if err != nil {
		return err
	}

	emailClient = client
	return nil
}

func CloseEmailClient() {
	log.Debug("Closing email client")
	emailClient.Close()
}

func SendEmail(to string, subject string, templateName string, body interface{}) error {
	log.Debugf("Sending email to %s with subject %s from template %s with data %v", to, subject, templateName, body)
	m := mail.NewMsg()
	if err := m.From(config.Config.Email.From); err != nil {
		log.Errorf("Failed to set email from address: %s", err)
		return err
	}
	if err := m.To(to); err != nil {
		log.Errorf("Failed to set email to address: %s", err)
		return err
	}
	m.Subject(subject)
	tmpl, err := template.ParseFiles(templateName)
	if err != nil {
		log.Errorf("Failed to parse email template %s: %s", templateName, err)
		return err
	}
	err = m.SetBodyHTMLTemplate(tmpl, body)
	if err != nil {
		log.Errorf("Failed to set email body: %s", err)
		return err
	}

	err = emailClient.DialAndSend(m)
	if err != nil {
		log.Errorf("Failed to send email: %s", err)
		return err
	}

	return nil
}

func SendEmailVerificationEmail(user *models.User, uev models.UserEmailVerification) error {
	log.Infof("Sending email verification email to %s", user.Email)
	data := struct {
		Username string
		Link     string
	}{
		Username: user.Username,
		Link:     fmt.Sprintf("%s/verify?id=%s&token=%s", config.Config.BaseURL, user.ID, uev.Token),
	}

	err := SendEmail(user.Email, "Verify your email address", "templates/email_verification.html", data)
	if err != nil {
		log.Errorf("Failed to send email verification email to %s: %s", user.Email, err)
		return err
	}

	return nil
}

func SendForgottenPasswordEmail(user *models.User, fp models.ForgottenPassword) error {
	log.Infof("Sending forgotten password email to %s", user.Email)
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
		log.Errorf("Failed to send forgotten password email to %s: %s", user.Email, err)
		return err
	}

	return nil
}
