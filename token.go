package auth

import (
	"time"
)

type Token struct {
	Id        string      `json:"id"`
	User      interface{} `json:"user"`
	ExpiresAt time.Time   `json:"expires_at"`
}
