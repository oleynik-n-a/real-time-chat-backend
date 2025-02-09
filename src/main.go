package main

import (
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	client     *mongo.Client
	collection *mongo.Collection
	jwtSecret  = []byte("your-256-bit-secret")
)

func main() {
	// Mongo connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://oleynik-n-a:oleynik-n-a-123@mongo:27017/chatdb?authSource=admin"))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	collection = client.Database("chatdb").Collection("users")

	router := gin.Default()

	router.POST("/signup", SignupHandler)
	router.POST("/login", LoginHandler)
	router.POST("/refresh-token", RefreshTokenHandler)
	router.POST("/send-message", SendMessageHandler)

	// Start server
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
