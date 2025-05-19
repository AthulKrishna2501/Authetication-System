package firebase

import (
	"context"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

func InitFirebase() (*auth.Client, error) {
	opt := option.WithCredentialsFile("firebase/firebasekey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, err
	}

	firebaseClient, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}

	return firebaseClient, nil
}
