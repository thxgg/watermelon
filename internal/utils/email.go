package utils

import (
	"github.com/gofiber/fiber/v2/log"
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

func SendEmail(to string, subject string, body string) error {
	m := mail.NewMsg()
	if err := m.From(config.Config.Email.From); err != nil {
		log.Fatalf("Failed to set From address: %s", err)
	}
	if err := m.To(to); err != nil {
		log.Fatalf("Failed to set To address: %s", err)
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextPlain, body)

	err := emailClient.DialAndSend(m)
	if err != nil {
		return err
	}

	return nil
}
