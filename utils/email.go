package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

func SendResetEmailWithSMTP(toEmail, resetLink string) error {
	from := os.Getenv("EMAIL")
	password := os.Getenv("GMAIL_APP_PASSWORD")

	to := []string{toEmail}
	subject := "Subject: Reset Your Password\n"
	body := fmt.Sprintf("Click this link to reset your password:\n\n%s", resetLink)
	msg := []byte(subject + "\n" + body)

	auth := smtp.PlainAuth("", from, password, "smtp.gmail.com")

	err := smtp.SendMail("smtp.gmail.com:587", auth, from, to, msg)
	if err != nil {
		return err
	}
	return nil
}
