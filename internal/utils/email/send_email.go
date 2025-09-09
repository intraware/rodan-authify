package email

import (
	"fmt"
	"net/smtp"
)

func SendMail(subject, content, recipientMail string) error {
	from := "your@email.com"
	password := "yourpassword"

	// Set up auth
	auth := smtp.PlainAuth("", from, password, "smtp.gmail.com")

	// Create message
	msg := []byte(fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, content))

	// Send email
	err := smtp.SendMail("smtp.gmail.com:587", auth, from, []string{recipientMail}, msg)
	if err != nil {
		return err
	}
	return nil
}
