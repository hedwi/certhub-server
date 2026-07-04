package controllers

import (
	"testing"
	"time"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupCertificateTestDB(t *testing.T) {
	t.Helper()
	ResetTestState()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Domain{}, &models.Certificate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	config.DB = db
}

func TestFailCertJob_AutoRenewKeepsActiveWhenCertificateExists(t *testing.T) {
	setupCertificateTestDB(t)

	user := models.User{Email: "user@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	domain := models.Domain{
		UserID:    user.ID,
		Domain:    "active.example.com",
		Status:    "generating",
		AutoRenew: true,
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}
	cert := models.Certificate{
		DomainID:  domain.ID,
		UserID:    user.ID,
		Domain:    domain.Domain,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := config.DB.Create(&cert).Error; err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	failCertJob(domain.ID, "ACME renew failed", true)

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "active" {
		t.Fatalf("status=%q, want active", updated.Status)
	}
	if updated.ErrorMessage != "ACME renew failed" {
		t.Fatalf("error_message=%q", updated.ErrorMessage)
	}
}

func TestFailCertJob_ManualIssueStillSetsError(t *testing.T) {
	setupCertificateTestDB(t)

	user := models.User{Email: "manual@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	domain := models.Domain{
		UserID: user.ID,
		Domain: "issue.example.com",
		Status: "generating",
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	failCertJob(domain.ID, "ACME obtain failed", false)

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "error" {
		t.Fatalf("status=%q, want error", updated.Status)
	}
}

func TestRollbackCancelledCertJob_RestoresVerified(t *testing.T) {
	setupCertificateTestDB(t)

	user := models.User{Email: "cancel@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	verifiedAt := time.Now().Add(-time.Hour)
	domain := models.Domain{
		UserID:          user.ID,
		Domain:          "cancel.example.com",
		Status:          "generating",
		CNameTarget:     "1.cname.test",
		CnameVerifiedAt: &verifiedAt,
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	rollbackCancelledCertJob(domain.ID, 1, false)

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "verified" {
		t.Fatalf("status=%q, want verified", updated.Status)
	}
	if updated.GeneratingSince != nil {
		t.Fatal("expected generating_since to be cleared")
	}
}

func TestMarkDomainCnameVerified_FromErrorStatus(t *testing.T) {
	setupCertificateTestDB(t)

	user := models.User{Email: "retry@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	domain := models.Domain{
		UserID:       user.ID,
		Domain:       "retry.example.com",
		Status:       "error",
		CNameTarget:  "1.cname.test",
		ErrorMessage: "ACME obtain failed",
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	if err := markDomainCnameVerified(domain.ID); err != nil {
		t.Fatalf("mark verified: %v", err)
	}

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "verified" {
		t.Fatalf("status=%q, want verified", updated.Status)
	}
	if updated.ErrorMessage != "" {
		t.Fatalf("error_message=%q, want empty", updated.ErrorMessage)
	}
	if updated.CnameVerifiedAt == nil {
		t.Fatal("expected cname_verified_at to be set")
	}
}
