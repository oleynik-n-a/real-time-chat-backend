package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var tinodeURL string = os.Getenv("TINODE_API_URL")

func sendTinodeRequest(method string, params map[string]interface{}) (*http.Response, error) {
	requestData := map[string]interface{}{
		"id":     1,
		"method": method,
		"params": params,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", tinodeURL+"/v1", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func encodeBasicAuth(login, password string) string {
	authString := login + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(authString))
}

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

	tinodeData := map[string]interface{}{
		"scheme": "basic",
		"secret": encodeBasicAuth(user.Email, req.Password),
		"login":  true,
		"desc": map[string]interface{}{
			"public": map[string]string{
				"fn": user.Email,
			},
		},
	}

	resp, err := sendTinodeRequest("acc", tinodeData)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println("Tinode registration failed")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user in Tinode"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user_id": user.ID,
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

	if err := user.CheckPassword(req.Password); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	tokenExpiryTime := user.TokenIssuedAt.Add(24 * time.Hour)
	if time.Now().Before(tokenExpiryTime) {
		c.JSON(http.StatusOK, gin.H{
			"message":           "Login successful",
			"token_still_valid": true,
			"token_expires_at":  tokenExpiryTime.Unix(),
			"user_id":           user.ID,
		})

		tinodeData := map[string]interface{}{
			"scheme": "basic",
			"secret": encodeBasicAuth(user.Email, req.Password),
		}

		resp, err := sendTinodeRequest("login", tinodeData)
		if err != nil || resp.StatusCode != http.StatusOK {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to login user in Tinode"})
			return
		}
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	tinodeData := map[string]interface{}{
		"scheme": "basic",
		"secret": encodeBasicAuth(user.Email, req.Password),
	}

	resp, err := sendTinodeRequest("login", tinodeData)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to login user in Tinode"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Login successful, new token issued",
		"token":            tokenString,
		"user_id":          user.ID,
		"token_expires_at": time.Now().Add(24 * time.Hour).Unix(),
	})
}

func RefreshTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	userID, ok := (*claims)["id"].(string)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	user := &User{}
	err = collection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(user)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	newTokenString, err := newToken.SignedString(jwtSecret)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	update := bson.M{"$set": bson.M{"token_issued_at": time.Now()}}
	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": user.ID}, update)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update token issue time"})
		return
	}

	tinodeData := map[string]interface{}{
		"scheme": "token",
		"secret": newTokenString,
	}

	resp, err := sendTinodeRequest("hi", tinodeData)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token in Tinode"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Token refreshed successfully",
		"token":            newTokenString,
		"user_id":          user.ID,
		"token_expires_at": time.Now().Add(24 * time.Hour).Unix(),
	})
}

func SendMessageHandler(c *gin.Context) {
	var msg Message
	if err := c.ShouldBindJSON(&msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	msg.ID = generateID()
	msg.CreatedAt = time.Now()

	generalCollection := client.Database("chatdb").Collection("General")
	_, err := generalCollection.InsertOne(context.Background(), msg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save message"})
		return
	}

	tinodeData := map[string]interface{}{
		"topic": "General",
		"content": map[string]interface{}{
			"text": msg.Text,
			"from": msg.UserID,
		},
	}

	resp, err := sendTinodeRequest("pub", tinodeData)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println("Tinode message send failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message to Tinode"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Message sent successfully",
		"message_id": msg.ID,
	})
}

func GetRecentMessagesHandler(c *gin.Context) {
	generalCollection := client.Database("chatdb").Collection("General")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var messages []Message
	cursor, err := generalCollection.Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(50))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
		return
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &messages); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse messages"})
		return
	}

	var messageTexts []string
	for _, msg := range messages {
		messageTexts = append(messageTexts, msg.Text)
	}

	c.JSON(http.StatusOK, messageTexts)
}
