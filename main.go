package main

import (
	"log"
	"user-auth/firebase"
	"user-auth/handlers"
	"user-auth/mongo"
	"user-auth/neo4j"
	"user-auth/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error Loading .env file %v", err)
	}

	firebaseClient, err := firebase.InitFirebase()
	if err != nil {
		log.Fatalf("Error Initialising firebase %v", err)
	}

	neo4jClient, err := neo4j.InitNeo4J()
	if err != nil {
		log.Fatalf("Error Initialising neo4j %v", err)
	}

	mongoClient, err := mongo.InitMongoClient()
	if err != nil {
		log.Fatalf("Error Initialising mongo %v", err)
	}

	authService := handlers.NewAuthService(firebaseClient, mongoClient, neo4jClient)
	router := gin.Default()

	router.POST("/signup", authService.Signup)
	router.POST("/login", authService.Login)
	router.POST("/guest", authService.GuestLogin)
	router.POST("/forgot-password", authService.ForgotPassword)
	router.POST("/reset-password", authService.ResetPassword)
	router.POST("/verify-credentials", authService.VerifyCredentials)

	protected := router.Group("/auth")
	protected.Use(utils.AuthMiddleware())
	{
		protected.POST("/change-credentials", authService.ChangeCredentials)
		protected.POST("/two-factor", authService.EnableTwoFactorAuthentication)
		protected.POST("/add-credentials", authService.AddOtherCredentials)
	}

	router.LoadHTMLGlob("templates/*")

	router.GET("/2fa/qr/:token", authService.ServeQRCodePage)
	router.GET("/2fa/qr/image/:token", authService.ServeQRCodeImage)

	if err := router.Run(":2500"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	router.Run(":2500")

}
