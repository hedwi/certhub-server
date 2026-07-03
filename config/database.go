package config

import (
	"fmt"
	"log"

	"github.com/hedwi/certhub-server/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	d := Cfg.Database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Asia/Shanghai",
		d.Host, d.User, d.Password, d.DBName, d.Port, d.SSLMode,
	)
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := removeDuplicateCertificates(DB); err != nil {
		log.Fatalf("Failed to deduplicate certificates: %v", err)
	}

	// Migrate the schema
	err = DB.AutoMigrate(
		&models.User{},
		&models.Domain{},
		&models.Certificate{},
		&models.AcmeAccount{},
		&models.DeployTarget{},
		&models.DeployJob{},
	)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}

// removeDuplicateCertificates keeps the newest row per domain_id before adding a unique index.
func removeDuplicateCertificates(db *gorm.DB) error {
	return db.Exec(`
		DELETE FROM certificates a
		USING certificates b
		WHERE a.domain_id = b.domain_id AND a.id < b.id
	`).Error
}
