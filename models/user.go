package models

import "time"

type User struct {
	UID             string    `json:"uid" bson:"uid"`
	Email           string    `json:"email" bson:"email"`
	PhoneNumber     string    `json:"phone_number" bson:"phone_number"`
	IsPhoneVerified bool      `json:"is_phone_verified" bson:"is_phone_verified"`
	IsEmailVerified bool      `json:"is_email_verified" bson:"is_email_verified"`
	IsGuestUser     bool      `json:"is_guest_user" bson:"is_guest_user"`
	PasswordHash    string    `json:"password_hash" bson:"password_hash"`
	Joint           []string  `json:"joint" bson:"joint"`
	IsBillableUser  bool      `json:"is_billable_user" bson:"is_billable_user"`
	Is2FNeeded      bool      `json:"is_2f_needed" bson:"is_2f_needed"`
	FirstName       string    `json:"first_name" bson:"first_name"`
	LastName        string    `json:"last_name" bson:"last_name"`
	CreatedAt       time.Time `json:"created_at" bson:"created_at"`
	LastLogin       time.Time `json:"last_login" bson:"last_login"`
	CountryOfOrigin string    `json:"country_of_origin" bson:"country_of_origin"`
	Address         string    `json:"address" bson:"address"`
}
