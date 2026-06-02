package models

import "time"

// AcmeAccount stores a persistent Let's Encrypt ACME account per user.
type AcmeAccount struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	UserID        uint      `gorm:"uniqueIndex;not null" json:"user_id"`
	Email         string    `gorm:"not null" json:"email"`
	PrivateKeyPEM []byte    `json:"-"`
	Registration  []byte    `json:"-"` // JSON-encoded registration.Resource
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
