package main

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        uuid.UUID "bson:\"_id\" json:\"id\""
	Email     string    "bson:\"email\" json:\"email\""
	Password  string    "bson:\"password\" json:\"-\""
	CreatedAt time.Time "bson:\"created_at\" json:\"created_at\""
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
		ID:        uuid.New(),
		Email:     email,
		Password:  password,
		CreatedAt: time.Now(),
	}
	if err := user.HashPassword(); err != nil {
		return nil, err
	}
	return user, nil
}
