package email

import (
	"fmt"
	"html/template"
	"time"

	"github.com/gofiber/fiber/v2/log"
	"github.com/thxgg/watermelon/app/users"
	"github.com/wneessen/go-mail"
)

const (
	emailVerificationSubject  = "Verify your email address"
	emailVerificationTemplate = "templates/email_verification.html"
	emailVerificationLink     = "/verify?id=%s&token=%s"
	forgottenPasswordSubject  = "Forgotten password"
	forgottenPasswordTemplate = "templates/forgotten_password.html"
	forgottenPasswordLink     = "/reset-password?id=%s&token=%s"
)

type Config struct {
	Host     string `validate:"hostname"`
	Port     int
	Username string
	Password string
	From     string `validate:"email"`
	SSL      bool
}

type Client struct {
	*mail.Client
	config *Config
}

func NewClient(config *Config) (*Client, error) {
	clientOptions := []mail.Option{
		mail.WithPort(config.Port),
		mail.WithSMTPAuth(mail.SMTPAuthLogin),
		mail.WithUsername(config.Username),
		mail.WithPassword(config.Password),
	}

	if config.SSL {
		clientOptions = append(clientOptions, mail.WithSSL())
	}

	client, err := mail.NewClient(config.Host, clientOptions...)
	return &Client{
		Client: client,
		config: config,
	}, err
}

func (client *Client) SendEmail(to string, subject string, templateName string, data interface{}) error {
	m := mail.NewMsg()
	if err := m.From(client.config.From); err != nil {
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
	err = m.SetBodyHTMLTemplate(tmpl, data)
	if err != nil {
		log.Errorf("Failed to set email body: %s", err)
		return err
	}

	err = client.DialAndSend(m)
	if err != nil {
		log.Errorf("Failed to send email: %s", err)
		return err
	}

	return nil
}

func (client *Client) SendEmailVerificationEmail(user *users.User, uev users.UserEmailVerification, baseURL string) error {
	log.Infof("Sending email verification email to %s", user.Email)
	data := struct {
		Username string
		Link     string
	}{
		Username: user.Username,
		Link:     baseURL + fmt.Sprintf(emailVerificationLink, user.ID, uev.Token),
	}

	err := client.SendEmail(user.Email, emailVerificationSubject, emailVerificationTemplate, data)
	if err != nil {
		log.Errorf("Failed to send email verification email to %s: %s", user.Email, err)
		return err
	}

	return nil
}

func (client *Client) SendForgottenPasswordEmail(user *users.User, fp users.ForgottenPassword, baseURL string) error {
	log.Infof("Sending forgotten password email to %s", user.Email)
	data := struct {
		Username  string
		Link      string
		ExpiresAt time.Time
	}{
		Username:  user.Username,
		Link:      baseURL + fmt.Sprintf(forgottenPasswordLink, user.ID, fp.Token),
		ExpiresAt: fp.ExpiresAt,
	}

	err := client.SendEmail(user.Email, forgottenPasswordSubject, forgottenPasswordTemplate, data)
	if err != nil {
		log.Errorf("Failed to send forgotten password email to %s: %s", user.Email, err)
		return err
	}

	return nil
}
