package firebase

import (
	"context"
	"errors"
	"os"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

func InitFirebase() (*auth.Client, error) {
	creds := os.Getenv("FIREBASE_CREDENTIALS")
	if creds == "" {
		return nil, errors.New("FIREBASE_CREDENTIALS environment variable is not set")
	}

	creds = strings.ReplaceAll(creds, `\n`, "\n")

	opt := option.WithCredentialsJSON([]byte(creds))
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, err
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}

	return client, nil
}
