package controllers

import (
	"testing"
	"time"

	"github.com/hedwi/certhub-server/models"
)

func TestToCnameConfigDTO_LiveCheck(t *testing.T) {
	verifiedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	domain := models.Domain{
		ID:              1,
		Domain:          "example.com",
		Status:          "verified",
		CNameTarget:     "1.cname.test",
		CnameVerifiedAt: &verifiedAt,
	}

	liveOK := true
	dto := toCnameConfigDTO(domain, &liveOK)
	if !dto.Verified || !dto.LiveChecked {
		t.Fatalf("expected live verified=true, got verified=%v liveChecked=%v", dto.Verified, dto.LiveChecked)
	}
	if dto.VerifiedAt == nil || *dto.VerifiedAt != "2026-07-01T12:00:00Z" {
		t.Fatalf("verifiedAt=%v", dto.VerifiedAt)
	}

	liveFail := false
	dto = toCnameConfigDTO(domain, &liveFail)
	if dto.Verified {
		t.Fatal("expected live verified=false when DNS check fails")
	}
	if dto.VerifiedAt == nil {
		t.Fatal("expected verifiedAt to remain from last POST verify")
	}
}

func TestToCnameConfigDTO_StoredStatusWhenNotLive(t *testing.T) {
	domain := models.Domain{
		ID:          2,
		Domain:      "stored.example.com",
		Status:      "verified",
		CNameTarget: "2.cname.test",
	}

	dto := toCnameConfigDTO(domain, nil)
	if !dto.Verified {
		t.Fatal("expected stored verified status")
	}
	if dto.LiveChecked {
		t.Fatal("expected liveChecked=false")
	}
}
