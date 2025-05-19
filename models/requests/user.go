package requests

type SignupRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
	Password    string `json:"password" binding:"omitempty,min=8"`
	FirstName   string `json:"first_name" binding:"omitempty"`
	LastName    string `json:"last_name" binding:"omitempty"`
}

type LoginRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
	Password    string `json:"password" binding:"required"`
}

type GuestRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
}

type ForgotPasswordRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
}

type ResetPasswordRequest struct {
    Email           string `json:"email" binding:"required,email"`
    CurrentPassword string `json:"current_password" binding:"required"`
    NewPassword     string `json:"new_password" binding:"required,min=8"`
    ConfirmPassword string `json:"confirm_password" binding:"required,min=8"`
}

type ChangeCredentialsRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
	Password    string `json:"password" binding:"omitempty,min=8"`
}

type TwoFactorRequest struct {
    Enable bool `json:"enable" binding:"required"`
}

type AddCredentialRequest struct {
	Email       string `json:"email" binding:"omitempty,email"`
	PhoneNumber string `json:"phone_number" binding:"omitempty"`
}
