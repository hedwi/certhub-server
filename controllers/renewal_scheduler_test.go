package controllers

import (
	"testing"
	"time"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRenewalSchedulerTestDB(t *testing.T) {
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

func TestRunStuckGeneratingCleanup_CancelsInflightJobAndRollsBack(t *testing.T) {
	setupRenewalSchedulerTestDB(t)

	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })
	config.Cfg.Renewal.GeneratingTimeout = "50ms"

	user := models.User{Email: "user@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	stale := time.Now().Add(-20 * time.Minute)
	domain := models.Domain{
		UserID:          user.ID,
		Domain:          "stuck.example.com",
		Status:          "generating",
		CNameTarget:     "1.cname.test",
		GeneratingSince: &stale,
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	ctx, _, release := beginCertJob(domain.ID)
	workerStarted := make(chan struct{})
	go func() {
		workerDone := beginDomainWorker(domain.ID)
		close(workerStarted)
		defer workerDone()
		<-ctx.Done()
		release()
	}()
	<-workerStarted
	if !certJobInflight(domain.ID) {
		t.Fatal("expected cert job to be in flight")
	}

	runStuckGeneratingCleanup(15 * time.Minute)

	if certJobInflight(domain.ID) {
		t.Fatal("expected timed-out cert job to be cancelled and released")
	}
	if err := ctx.Err(); err == nil {
		t.Fatal("expected cert job context to be cancelled")
	}

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "error" {
		t.Fatalf("status=%q, want error", updated.Status)
	}
	if updated.GeneratingSince != nil {
		t.Fatal("expected generating_since to be cleared")
	}
	if updated.ErrorMessage != stuckGeneratingMessage {
		t.Fatalf("error_message=%q, want %q", updated.ErrorMessage, stuckGeneratingMessage)
	}
}

func TestRunStuckGeneratingCleanup_RollsBackToActiveWhenCertExists(t *testing.T) {
	setupRenewalSchedulerTestDB(t)

	user := models.User{Email: "renew@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	stale := time.Now().Add(-20 * time.Minute)
	domain := models.Domain{
		UserID:          user.ID,
		Domain:          "renew-stuck.example.com",
		Status:          "generating",
		CNameTarget:     "2.cname.test",
		GeneratingSince: &stale,
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}
	cert := models.Certificate{
		DomainID:  domain.ID,
		UserID:    user.ID,
		Domain:    domain.Domain,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := config.DB.Create(&cert).Error; err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ctx, _, release := beginCertJob(domain.ID)
	workerStarted := make(chan struct{})
	go func() {
		workerDone := beginDomainWorker(domain.ID)
		close(workerStarted)
		defer workerDone()
		<-ctx.Done()
		release()
	}()
	<-workerStarted

	runStuckGeneratingCleanup(15 * time.Minute)

	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "active" {
		t.Fatalf("status=%q, want active", updated.Status)
	}
}

func TestTryAutoRenewDomain_SkipsWhenAutoRenewDisabled(t *testing.T) {
	setupRenewalSchedulerTestDB(t)

	user := models.User{Email: "disabled@test.example", Password: "secret"}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	domain := models.Domain{
		UserID:      user.ID,
		Domain:      "no-auto.example.com",
		Status:      "active",
		CNameTarget: "3.cname.test",
		AutoRenew:   false,
	}
	if err := config.DB.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	tryAutoRenewDomain(domain)

	if certJobInflight(domain.ID) {
		t.Fatal("expected auto renewal to be skipped when disabled")
	}
	var updated models.Domain
	if err := config.DB.First(&updated, domain.ID).Error; err != nil {
		t.Fatalf("reload domain: %v", err)
	}
	if updated.Status != "active" {
		t.Fatalf("status=%q, want active", updated.Status)
	}
}
