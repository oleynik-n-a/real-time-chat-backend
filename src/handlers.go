package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SignupHandler(c *gin.Context) {
    var req AuthRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    existing := &User{}
    err := collection.FindOne(context.Background(), bson.M{"email": req.Email}).Decode(existing)
    if err == nil {
        c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "User already exists"})
        return
    } else if err != mongo.ErrNoDocuments {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    }

    user, err := NewUser(req.Email, req.Password)
    if err != nil {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }

    _, err = collection.InsertOne(context.Background(), user)
    if err != nil {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }

    c.JSON(http.StatusCreated, gin.H{
        "message": "User registered successfully",
        "user_id": user.ID.String(),
    })
}

func LoginHandler(c *gin.Context) {
    var req AuthRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    user := &User{}
    err := collection.FindOne(context.Background(), bson.M{"email": req.Email}).Decode(user)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        } else {
            c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        }
        return
    }

	log.Println("Stored password:", user.Password)


    if err := user.CheckPassword(req.Password); err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "id":    user.ID.String(),
        "email": user.Email,
        "exp":   time.Now().Add(time.Hour * 24).Unix(),
    })

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

	c.JSON(http.StatusOK, gin.H{
        "token":   tokenString,
        "user_id": user.ID.String(),
        "message": "Login successful",
    })
}
