package models

import (
	"time"

	"gorm.io/gorm"
)

type Domain struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	UserID    uint           `gorm:"index;not null" json:"user_id"`
	Domain    string         `gorm:"uniqueIndex;not null" json:"domain"`
	Status    string         `gorm:"default:'pending'" json:"status"` // pending, verified, active, error
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Certificate struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DomainID  uint      `gorm:"index;not null" json:"domain_id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	Domain    string    `json:"domain"`
	CertPEM   []byte    `json:"-"`
	KeyPEM    []byte    `json:"-"`
	Issuer    []byte    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
