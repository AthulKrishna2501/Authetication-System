package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"user-auth/models"
	"user-auth/models/requests"
	"user-auth/utils"

	"firebase.google.com/go/v4/auth"
	"github.com/gin-gonic/gin"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	firebaseAuth *auth.Client
	mongoClient  *mongo.Client
	neo4jClient  neo4j.DriverWithContext
}

func NewAuthService(firebaseAuth *auth.Client, mongoClient *mongo.Client, neo4jClient neo4j.DriverWithContext) *AuthService {
	return &AuthService{
		firebaseAuth: firebaseAuth,
		mongoClient:  mongoClient,
		neo4jClient:  neo4jClient,
	}
}

func (as *AuthService) Signup(c *gin.Context) {
	var req requests.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	if req.Password != "" && !utils.IsValidPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password format"})
		return
	}

	if req.PhoneNumber != "" && !utils.IsValidPhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
		return
	}

	params := (&auth.UserToCreate{}).
		Email(req.Email).
		PhoneNumber(req.PhoneNumber).
		Password(req.Password)

	userRecord, err := as.firebaseAuth.CreateUser(context.Background(), params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user", "err": err.Error()})
		return
	}

	var passwordHash string
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		passwordHash = string(hash)
	}

	user := models.User{
		UID:             userRecord.UID,
		Email:           req.Email,
		PhoneNumber:     req.PhoneNumber,
		IsPhoneVerified: false,
		IsEmailVerified: false,
		IsGuestUser:     req.Password == "",
		PasswordHash:    passwordHash,
		Joint:           []string{"Capcons"},
		IsBillableUser:  false,
		Is2FNeeded:      false,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		CreatedAt:       time.Now(),
		LastLogin:       time.Now(),
		CountryOfOrigin: "",
		Address:         "",
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user in MongoDB"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            CREATE (u:User {
                uid: $uid,
                email: $email,
                phoneNumber: $phoneNumber,
                isPhoneVerified: $isPhoneVerified,
                isEmailVerified: $isEmailVerified,
                isGuestUser: $isGuestUser,
                firstName: $firstName,
                lastName: $lastName,
                createdAt: $createdAt,
                lastLogin: $lastLogin
            })
        `
		params := map[string]interface{}{
			"uid":             user.UID,
			"email":           user.Email,
			"phoneNumber":     user.PhoneNumber,
			"isPhoneVerified": user.IsPhoneVerified,
			"isEmailVerified": user.IsEmailVerified,
			"isGuestUser":     user.IsGuestUser,
			"firstName":       user.FirstName,
			"lastName":        user.LastName,
			"createdAt":       user.CreatedAt.UTC(),
			"lastLogin":       user.LastLogin.UTC(),
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user in Neo4j", "err": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status":  201,
		"message": "User signup successfull",
	})
}

func (as *AuthService) Login(c *gin.Context) {
	var req requests.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	userRecord, err := as.firebaseAuth.GetUserByEmail(context.Background(), req.Email)
	if err != nil && req.Email != "" {
		userRecord, err = as.firebaseAuth.GetUserByPhoneNumber(context.Background(), req.PhoneNumber)
	}
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	var user models.User
	err = collection.FindOne(context.Background(), bson.M{"uid": userRecord.UID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if user.IsGuestUser || user.PasswordHash == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Guest users cannot login with password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	now := time.Now()
	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": userRecord.UID}, bson.M{
		"$set": bson.M{"last_login": now},
	})
	if err != nil {
		log.Println("MongoDB update error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update last login"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MERGE (u:User {uid: $uid})
            SET u.lastLogin = $lastLogin
        `
		params := map[string]interface{}{
			"uid":       userRecord.UID,
			"lastLogin": now.UTC(),
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update last login in Neo4j"})
		return
	}

	token, err := utils.GenerateJWT(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  200,
		"message": "Login successful",
		"token":   token,
	})
}

func (as *AuthService) GuestLogin(c *gin.Context) {
	var req requests.GuestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	if req.PhoneNumber != "" && !utils.IsValidPhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
		return
	}

	var userRecord *auth.UserRecord
	var err error
	if req.Email != "" {
		userRecord, err = as.firebaseAuth.GetUserByEmail(context.Background(), req.Email)
	} else {
		userRecord, err = as.firebaseAuth.GetUserByPhoneNumber(context.Background(), req.PhoneNumber)
	}

	if err != nil {
		params := (&auth.UserToCreate{})

		if req.Email != "" {
			params = params.Email(req.Email)
		}

		if req.PhoneNumber != "" {
			params = params.PhoneNumber(req.PhoneNumber)
		}
		userRecord, err = as.firebaseAuth.CreateUser(context.Background(), params)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create guest user", "err": err.Error()})
			return
		}

		user := models.User{
			UID:             userRecord.UID,
			Email:           req.Email,
			PhoneNumber:     req.PhoneNumber,
			IsPhoneVerified: false,
			IsEmailVerified: false,
			IsGuestUser:     true,
			PasswordHash:    "",
			Joint:           []string{"Capcons"},
			IsBillableUser:  false,
			Is2FNeeded:      false,
			FirstName:       "",
			LastName:        "",
			CreatedAt:       time.Now(),
			LastLogin:       time.Now(),
			CountryOfOrigin: "",
			Address:         "",
		}

		collection := as.mongoClient.Database("auth").Collection("users")
		_, err = collection.InsertOne(context.Background(), user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store guest user"})
			return
		}

		session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
		defer session.Close(context.Background())

		_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
			query := `
                CREATE (u:User {
                    uid: $uid,
                    email: $email,
                    phoneNumber: $phoneNumber,
                    isPhoneVerified: $isPhoneVerified,
                    isEmailVerified: $isEmailVerified,
                    isGuestUser: $isGuestUser,
                    firstName: $firstName,
                    lastName: $lastName,
                    createdAt: $createdAt,
                    lastLogin: $lastLogin
                })
            `
			params := map[string]interface{}{
				"uid":             user.UID,
				"email":           user.Email,
				"phoneNumber":     user.PhoneNumber,
				"isPhoneVerified": user.IsPhoneVerified,
				"isEmailVerified": user.IsEmailVerified,
				"isGuestUser":     user.IsGuestUser,
				"firstName":       user.FirstName,
				"lastName":        user.LastName,
				"createdAt":       user.CreatedAt,
				"lastLogin":       user.LastLogin,
			}
			_, err := tx.Run(context.Background(), query, params)
			return nil, err
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store guest user in Neo4j"})
			return
		}
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	var user models.User
	err = collection.FindOne(context.Background(), bson.M{"uid": userRecord.UID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	now := time.Now()
	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": userRecord.UID}, bson.M{
		"$set": bson.M{"last_login": now},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update last login"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MERGE (u:User {uid: $uid})
            SET u.lastLogin = $lastLogin
        `
		params := map[string]interface{}{
			"uid":       userRecord.UID,
			"lastLogin": now.UTC(),
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update last login in Neo4j", "err": err.Error()})
		return
	}

	token, err := utils.GenerateJWT(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  200,
		"message": "Guest login successful",
		"token":   token,
	})
}

func (as *AuthService) VerifyCredentials(c *gin.Context) {
	var req requests.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	userRecord, err := as.firebaseAuth.GetUserByEmail(context.Background(), req.Email)
	if err != nil && req.Email != "" {
		userRecord, err = as.firebaseAuth.GetUserByPhoneNumber(context.Background(), req.PhoneNumber)
	}
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	var user models.User
	err = collection.FindOne(context.Background(), bson.M{"uid": userRecord.UID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if user.IsGuestUser || user.PasswordHash == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Guest users cannot verify credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"uid":     userRecord.UID,
		"message": "Credentials verified",
	})
}

func (as *AuthService) ForgotPassword(c *gin.Context) {
	var req requests.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	if req.PhoneNumber != "" && !utils.IsValidPhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
		return
	}

	if req.Email != "" {
		resetLink, err := as.firebaseAuth.PasswordResetLinkWithSettings(context.Background(), req.Email, nil)
		if err != nil {
			log.Println("Failed to generate password reset link:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset link"})
			return
		}

		err = utils.SendResetEmailWithSMTP(req.Email, resetLink)
		if err != nil {
			log.Println("Failed to send reset email via SMTP:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send reset email"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent successfully"})
		return
	}

	c.JSON(http.StatusNotImplemented, gin.H{"error": "Phone-based password reset not supported"})
}

func (as *AuthService) ResetPassword(c *gin.Context) {
	var req requests.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" || req.CurrentPassword == "" || req.NewPassword == "" || req.ConfirmPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email, current password, new password, and confirm password are required"})
		return
	}

	if !utils.IsValidPassword(req.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid new password format"})
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password and confirm password do not match"})
		return
	}

	if req.NewPassword == req.CurrentPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password must be different from current password"})
		return
	}

	userRecord, err := as.firebaseAuth.GetUserByEmail(context.Background(), req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	var user models.User
	err = collection.FindOne(context.Background(), bson.M{"uid": userRecord.UID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}

	if user.IsGuestUser || user.PasswordHash == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Guest users cannot reset passwords"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid current password"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	_, err = as.firebaseAuth.UpdateUser(context.Background(), userRecord.UID, (&auth.UserToUpdate{}).Password(req.NewPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password in Firebase"})
		return
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": userRecord.UID}, bson.M{
		"$set": bson.M{
			"password_hash": string(hash),
			"is_guest_user": false,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password in MongoDB"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MATCH (u:User {uid: $uid})
            SET u.passwordHash = $passwordHash
        `
		params := map[string]interface{}{
			"uid":          userRecord.UID,
			"passwordHash": string(hash),
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password in Neo4j"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully",
	})
}

func (as *AuthService) ChangeCredentials(c *gin.Context) {
	var req requests.ChangeCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one credential must be provided"})
		return
	}

	if req.PhoneNumber != "" && !utils.IsValidPhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
		return
	}

	if req.Password != "" && !utils.IsValidPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password format"})
		return
	}

	uid, exists := c.Get("uid")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userRecord, err := as.firebaseAuth.GetUser(context.Background(), uid.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	update := auth.UserToUpdate{}
	mongoUpdate := bson.M{}
	if req.Email != "" {
		update.Email(req.Email)
		mongoUpdate["email"] = req.Email
		mongoUpdate["is_email_verified"] = false
	}
	if req.PhoneNumber != "" {
		update.PhoneNumber(req.PhoneNumber)
		mongoUpdate["phone_number"] = req.PhoneNumber
		mongoUpdate["is_phone_verified"] = false
	}
	if req.Password != "" {
		update.Password(req.Password)
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		mongoUpdate["password_hash"] = string(hash)
		mongoUpdate["is_guest_user"] = false
	}

	_, err = as.firebaseAuth.UpdateUser(context.Background(), userRecord.UID, &update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update credentials"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": userRecord.UID}, bson.M{
		"$set": mongoUpdate,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update MongoDB"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MATCH (u:User {uid: $uid})
            SET u.email = $email, u.phoneNumber = $phoneNumber
        `
		params := map[string]interface{}{
			"uid":         userRecord.UID,
			"email":       req.Email,
			"phoneNumber": req.PhoneNumber,
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update Neo4j"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Credentials updated successfully",
	})
}

func (as *AuthService) EnableTwoFactorAuthentication(c *gin.Context) {
	var req requests.TwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	uid, exists := c.Get("uid")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	uidStr, ok := uid.(string)
	if !ok || uidStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	var user models.User
	err := collection.FindOne(context.Background(), bson.M{"uid": uidStr}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
		return
	}



	var secret string
	var qrLink string
	if req.Enable {
		secret, err = utils.GenerateTOTPSecret(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP secret"})
			return
		}

		qrCodeData, err := utils.GenerateTOTPQRCodeURL(user.Email, secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
			return
		}

		token, err := utils.StoreQRCodeData(as.mongoClient, uidStr, secret, qrCodeData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store QR code data"})
			return
		}

		qrLink = fmt.Sprintf("%s/2fa/qr/%s", os.Getenv("BASE_URL"), token)
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": uidStr}, bson.M{
		"$set": bson.M{
			"is_2f_needed": req.Enable,
			"totp_secret":  secret,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update two-factor authentication in MongoDB"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MATCH (u:User {uid: $uid})
            SET u.is2FNeeded = $is2FNeeded
        `
		params := map[string]interface{}{
			"uid":        uidStr,
			"is2FNeeded": req.Enable,
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update two-factor authentication in Neo4j"})
		return
	}

	response := gin.H{
		"message": "Two-factor authentication updated successfully",
	}
	if req.Enable {
		response["qrLink"] = qrLink
	}
	c.JSON(http.StatusOK, response)
}

func (as *AuthService) ServeQRCodePage(c *gin.Context) {
	token := c.Param("token")
	log.Printf("Attempting to serve QR code page for token: %s", token)

	collection := as.mongoClient.Database("auth").Collection("qrcodes")
	var qrDoc bson.M
	err := collection.FindOne(context.Background(), bson.M{"token": token}).Decode(&qrDoc)
	if err != nil {
		log.Printf("QR code not found for token: %s, error: %v", token, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "QR code not found or expired"})
		return
	}

	var expiresAt time.Time
	if qrDoc["expires_at"] == nil {
		log.Printf("expires_at is null for token: %s", token)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	switch v := qrDoc["expires_at"].(type) {
	case time.Time:
		expiresAt = v
	case string:
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			log.Printf("Failed to parse expires_at string for token: %s, value: %v, error: %v", token, v, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
			return
		}
		expiresAt = parsed
	case primitive.DateTime:
		expiresAt = time.Unix(int64(v)/1000, (int64(v)%1000)*1000000)
	default:
		log.Printf("Invalid expires_at type for token: %s, got: %T, value: %v", token, v, v)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	if expiresAt.Before(time.Now()) {
		log.Printf("QR code expired for token: %s, expires_at: %v, now: %v", token, expiresAt, time.Now())
		c.JSON(http.StatusGone, gin.H{"error": "QR code expired"})
		return
	}

	secret, ok := qrDoc["secret"].(string)
	if !ok {
		log.Printf("Invalid secret type for token: %s, got: %T", token, qrDoc["secret"])
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	log.Printf("Serving QR code page for token: %s, expires_at: %v", token, expiresAt)
	c.HTML(http.StatusOK, "index.html", gin.H{
		"token":  token,
		"secret": secret,
	})
}

func (as *AuthService) ServeQRCodeImage(c *gin.Context) {
	token := c.Param("token")
	log.Printf("Attempting to serve QR code image for token: %s", token)

	collection := as.mongoClient.Database("auth").Collection("qrcodes")
	var qrDoc bson.M
	err := collection.FindOne(context.Background(), bson.M{"token": token}).Decode(&qrDoc)
	if err != nil {
		log.Printf("QR code not found for token: %s, error: %v", token, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "QR code not found or expired"})
		return
	}

	var expiresAt time.Time
	if qrDoc["expires_at"] == nil {
		log.Printf("expires_at is null for token: %s", token)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	switch v := qrDoc["expires_at"].(type) {
	case time.Time:
		expiresAt = v
	case string:
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			log.Printf("Failed to parse expires_at string for token: %s, value: %v, error: %v", token, v, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
			return
		}
		expiresAt = parsed
	case primitive.DateTime:
		expiresAt = time.Unix(int64(v)/1000, (int64(v)%1000)*1000000)
	default:
		log.Printf("Invalid expires_at type for token: %s, got: %T, value: %v", token, v, v)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	if expiresAt.Before(time.Now()) {
		log.Printf("QR code expired for token: %s, expires_at: %v, now: %v", token, expiresAt, time.Now())
		c.JSON(http.StatusGone, gin.H{"error": "QR code expired"})
		return
	}

	qrCodeData, ok := qrDoc["qrCodeData"].(primitive.Binary)
	if !ok {
		log.Printf("Invalid qrCodeData type for token: %s, got: %T", token, qrDoc["qrCodeData"])
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid QR code data"})
		return
	}

	log.Printf("Serving QR code image for token: %s, data length: %d, expires_at: %v", token, len(qrCodeData.Data), expiresAt)
	c.Data(http.StatusOK, "image/png", qrCodeData.Data)
}

func (as *AuthService) AddOtherCredentials(c *gin.Context) {
	var req requests.AddCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	uid, exists := c.Get("uid")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userRecord, err := as.firebaseAuth.GetUser(context.Background(), uid.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if req.Email == "" && req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or phone number required"})
		return
	}

	if req.PhoneNumber != "" && !utils.IsValidPhoneNumber(req.PhoneNumber) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
		return
	}

	update := auth.UserToUpdate{}
	mongoUpdate := bson.M{}
	if req.Email != "" && userRecord.Email == "" {
		update.Email(req.Email)
		mongoUpdate["email"] = req.Email
		mongoUpdate["is_email_verified"] = false
	}
	if req.PhoneNumber != "" && userRecord.PhoneNumber == "" {
		update.PhoneNumber(req.PhoneNumber)
		mongoUpdate["phone_number"] = req.PhoneNumber
		mongoUpdate["is_phone_verified"] = false
	}

	if len(mongoUpdate) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No new credentials to add"})
		return
	}

	_, err = as.firebaseAuth.UpdateUser(context.Background(), userRecord.UID, &update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update credentials"})
		return
	}

	collection := as.mongoClient.Database("auth").Collection("users")
	_, err = collection.UpdateOne(context.Background(), bson.M{"uid": userRecord.UID}, bson.M{
		"$set": mongoUpdate,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update MongoDB"})
		return
	}

	session := as.neo4jClient.NewSession(context.Background(), neo4j.SessionConfig{})
	defer session.Close(context.Background())

	_, err = session.ExecuteWrite(context.Background(), func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
            MATCH (u:User {uid: $uid})
            SET u.email = $email, u.phoneNumber = $phoneNumber
        `
		params := map[string]interface{}{
			"uid":         userRecord.UID,
			"email":       req.Email,
			"phoneNumber": req.PhoneNumber,
		}
		_, err := tx.Run(context.Background(), query, params)
		return nil, err
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update Neo4j"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Credentials added successfully",
	})
}
