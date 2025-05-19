package firebase

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

func InitFirebase() (*auth.Client, error) {
	creds := os.Getenv("FIREBASE_CREDENTIALS")
	if creds == "" {
		return nil, errors.New("FIREBASE_CREDENTIALS_BASE64 is not set")
	}

	decoded, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		return nil, fmt.Errorf("error decoding FIREBASE_CREDENTIALS_BASE64: %w", err)
	}

	opt := option.WithCredentialsJSON(decoded)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firebase app: %w", err)
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error getting Auth client: %w", err)
	}

	return client, nil
}
