package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID            string    "bson:\"_id\" json:\"id\""
	Email         string    "bson:\"email\" json:\"email\""
	Password      string    "bson:\"password\" json:\"-\""
	CreatedAt     time.Time "bson:\"created_at\" json:\"created_at\""
	TokenIssuedAt time.Time "bson:\"token_issued_at\" json:\"token_issued_at\""
}

type AuthRequest struct {
	Email    string "json:\"email\" validate:\"required,email\""
	Password string "json:\"password\" validate:\"required,min=8,max=16\""
}

func (u *User) HashPassword() error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashed)
	return nil
}

func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}

func NewUser(email, password string) (*User, error) {
	user := &User{
		ID:        generateID(),
		Email:     email,
		Password:  password,
		CreatedAt: time.Now(),
	}
	if err := user.HashPassword(); err != nil {
		return nil, err
	}
	return user, nil
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
