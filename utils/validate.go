package utils

import "regexp"

func IsValidPassword(password string) bool {
	hasMinLength := len(password) >= 8
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#~$%^&*]`).MatchString(password)
	return hasMinLength && hasNumber && hasLetter && hasSpecial
}

func IsValidPhoneNumber(phone string) bool {
	phoneRegex := regexp.MustCompile(`^\+\d{1,3}\d{9,12}$`)
	return phoneRegex.MatchString(phone)
}
