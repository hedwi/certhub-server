package models

import (
	"time"

	"gorm.io/gorm"
)

type Domain struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	UserID       uint           `gorm:"index;not null" json:"user_id"`
	Domain       string         `gorm:"uniqueIndex;not null" json:"domain"`
	Status       string         `gorm:"default:'pending'" json:"status"` // pending, verified, generating, active, error
	CNameTarget  string         `json:"cname_target"` // per-domain delegation FQDN
	DNSProvider  string         `json:"dns_provider,omitempty"`
	DNSZoneID    string         `json:"dns_zone_id,omitempty"`
	ErrorMessage string         `gorm:"type:text" json:"error_message,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type Certificate struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	DomainID      uint      `gorm:"index;not null" json:"domain_id"`
	UserID        uint      `gorm:"index;not null" json:"user_id"`
	Domain        string    `json:"domain"`
	CertPEM       []byte    `json:"-"`
	KeyPEM        []byte    `json:"-"`
	Issuer        []byte    `json:"-"`
	CertURL       string    `json:"-"`
	CertStableURL string    `json:"-"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
