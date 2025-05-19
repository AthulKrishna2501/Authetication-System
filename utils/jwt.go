package utils

import (
	"net/http"
	"os"
	"strings"
	"time"
	"user-auth/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	UID         string `json:"uid"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	IsGuestUser bool   `json:"is_guest_user"`
	jwt.RegisteredClaims
}

func GenerateJWT(user *models.User) (string, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))
	claims := &Claims{
		UID:         user.UID,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		IsGuestUser: user.IsGuestUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.UID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(parts[1], &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("uid", claims.UID)
		c.Set("is_guest_user", claims.IsGuestUser)
		c.Next()
	}
}
