package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/pquerna/otp"
	"github.com/skip2/go-qrcode"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/pquerna/otp/totp"
)

func GenerateTOTPSecret(email string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "YourApp",
		AccountName: email,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP key: %v", err)
	}
	return key.Secret(), nil
}

func GenerateTOTPQRCodeURL(email, secret string) ([]byte, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", "YourApp", email, secret, "YourApp"))
	if err != nil {
		return nil, fmt.Errorf("failed to create OTP key: %v", err)
	}

	png, err := qrcode.Encode(key.String(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %v", err)
	}

	return png, nil
}

func GenerateTOTPCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %v", err)
	}
	return code, nil
}

func VerifyTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

func GenerateResetCode() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}
func StoreQRCodeData(mongoClient *mongo.Client, uid, secret string, qrCodeData []byte) (string, error) {
	tokenBytes := make([]byte, 16)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %v", err)
	}
	token := hex.EncodeToString(tokenBytes)

	qrCodeDoc := bson.M{
		"token":      token,
		"uid":        uid,
		"secret":     secret,
		"qrCodeData": qrCodeData,
		"created_at": time.Now(),
		"expires_at": time.Now().Add(15 * time.Minute),
	}

	collection := mongoClient.Database("auth").Collection("qrcodes")
	_, err = collection.InsertOne(context.Background(), qrCodeDoc)
	if err != nil {
		return "", fmt.Errorf("failed to store QR code data: %v", err)
	}

	log.Printf("Stored QR code token: %s for UID: %s, expires at: %v", token, uid, qrCodeDoc["expires_at"])
	return token, nil
}
