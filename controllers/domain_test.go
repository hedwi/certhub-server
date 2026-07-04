package controllers

import (
	"errors"
	"testing"
	"time"

	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupDomainTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Domain{}, &models.Certificate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	config.DB = db
}

func TestIsUnclaimedDomain(t *testing.T) {
	setupDomainTestDB(t)
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })
	config.Cfg.Domain.UnclaimedErrorRelease = "72h"

	owner := models.User{Email: "owner@test.example", Password: "hash"}
	if err := config.DB.Create(&owner).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	staleUpdated := time.Now().Add(-96 * time.Hour)
	recentUpdated := time.Now().Add(-1 * time.Hour)
	verifiedAt := time.Now().Add(-48 * time.Hour)

	cases := []struct {
		name     string
		domain   models.Domain
		withCert bool
		want     bool
	}{
		{name: "pending", domain: models.Domain{UserID: owner.ID, Domain: "pending.example.com", Status: "pending"}, want: true},
		{name: "verified", domain: models.Domain{UserID: owner.ID, Domain: "verified.example.com", Status: "verified"}, want: false},
		{name: "generating", domain: models.Domain{UserID: owner.ID, Domain: "generating.example.com", Status: "generating"}, want: false},
		{name: "active", domain: models.Domain{UserID: owner.ID, Domain: "active.example.com", Status: "active"}, want: false},
		{name: "error without cname verified", domain: models.Domain{UserID: owner.ID, Domain: "error-new.example.com", Status: "error", UpdatedAt: recentUpdated}, want: true},
		{name: "error cname verified recent", domain: models.Domain{UserID: owner.ID, Domain: "error-recent.example.com", Status: "error", UpdatedAt: recentUpdated, CnameVerifiedAt: &verifiedAt}, want: false},
		{name: "error cname verified stale", domain: models.Domain{UserID: owner.ID, Domain: "error-stale.example.com", Status: "error", UpdatedAt: staleUpdated, CnameVerifiedAt: &verifiedAt}, want: true},
		{name: "error with cert", domain: models.Domain{UserID: owner.ID, Domain: "error-cert.example.com", Status: "error"}, withCert: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := config.DB.Create(&tc.domain).Error; err != nil {
				t.Fatalf("create domain: %v", err)
			}
			if tc.withCert {
				cert := models.Certificate{DomainID: tc.domain.ID, UserID: owner.ID, Domain: tc.domain.Domain}
				if err := config.DB.Create(&cert).Error; err != nil {
					t.Fatalf("create cert: %v", err)
				}
			}
			if got := isUnclaimedDomain(tc.domain); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssignUnclaimedDomainToUser(t *testing.T) {
	setupDomainTestDB(t)

	squatter := models.User{Email: "squatter@test.example", Password: "hash"}
	claimer := models.User{Email: "claimer@test.example", Password: "hash"}
	if err := config.DB.Create(&squatter).Error; err != nil {
		t.Fatalf("create squatter: %v", err)
	}
	if err := config.DB.Create(&claimer).Error; err != nil {
		t.Fatalf("create claimer: %v", err)
	}

	pending := models.Domain{
		UserID:      squatter.ID,
		Domain:      "claim-me.example.com",
		Status:      "pending",
		CNameTarget: "99.cname.test.example",
		AutoRenew:   true,
	}
	if err := config.DB.Create(&pending).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}

	got, err := assignUnclaimedDomainToUser(pending.ID, claimer.ID)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.UserID != claimer.ID {
		t.Fatalf("user_id=%d, want %d", got.UserID, claimer.ID)
	}
	if got.Status != "verified" {
		t.Fatalf("status=%q, want verified", got.Status)
	}
	if got.CnameVerifiedAt == nil {
		t.Fatal("expected cname_verified_at to be set")
	}

	_, err = assignUnclaimedDomainToUser(pending.ID, claimer.ID)
	if !errors.Is(err, errDomainClaimLost) {
		t.Fatalf("second assign err=%v, want errDomainClaimLost", err)
	}
}

func TestAssignUnclaimedDomainToUser_FromError(t *testing.T) {
	setupDomainTestDB(t)

	squatter := models.User{Email: "squatter@test.example", Password: "hash"}
	claimer := models.User{Email: "claimer@test.example", Password: "hash"}
	config.DB.Create(&squatter)
	config.DB.Create(&claimer)

	errored := models.Domain{
		UserID:      squatter.ID,
		Domain:      "error-claim.example.com",
		Status:      "error",
		CNameTarget: "88.cname.test.example",
		AutoRenew:   true,
	}
	config.DB.Create(&errored)

	got, err := assignUnclaimedDomainToUser(errored.ID, claimer.ID)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.UserID != claimer.ID || got.Status != "verified" {
		t.Fatalf("got user_id=%d status=%q, want claimer verified", got.UserID, got.Status)
	}
}

func TestAssignUnclaimedDomainToUser_RejectsNonClaimable(t *testing.T) {
	setupDomainTestDB(t)

	owner := models.User{Email: "owner@test.example", Password: "hash"}
	other := models.User{Email: "other@test.example", Password: "hash"}
	config.DB.Create(&owner)
	config.DB.Create(&other)

	active := models.Domain{
		UserID:    owner.ID,
		Domain:    "taken.example.com",
		Status:    "active",
		AutoRenew: true,
	}
	config.DB.Create(&active)

	_, err := assignUnclaimedDomainToUser(active.ID, other.ID)
	if !errors.Is(err, errDomainClaimLost) {
		t.Fatalf("assign active domain err=%v, want errDomainClaimLost", err)
	}
}
