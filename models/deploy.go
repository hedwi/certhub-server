package models

import "time"

type DeployTarget struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	DomainID       uint       `gorm:"index;not null" json:"domain_id"`
	UserID         uint       `gorm:"index;not null" json:"user_id"`
	Name           string     `gorm:"not null" json:"name"`
	Type           string     `gorm:"not null" json:"type"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Enabled        bool       `gorm:"default:true" json:"enabled"`
	AuthType       string     `json:"auth_type"`
	SSHUser        string     `json:"ssh_user"`
	PrivateKeyPEM  []byte     `json:"-"`
	PasswordEnc    []byte     `json:"-"`
	CertPath       string     `json:"cert_path"`
	ReloadCommand  string     `json:"reload_command"`
	LastDeployAt   *time.Time `json:"last_deploy_at"`
	LastStatus     string     `json:"last_status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type DeployJob struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	DomainID   uint       `gorm:"index;not null" json:"domain_id"`
	UserID     uint       `gorm:"index;not null" json:"user_id"`
	Status     string     `gorm:"not null" json:"status"`
	TargetsJSON []byte    `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
}
