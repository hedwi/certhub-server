package config

import (
	"testing"
	"time"
)

func TestDelegationTarget(t *testing.T) {
	Cfg.Domain.CNameTarget = "cname.yourservice.com"
	got := DelegationTarget(42)
	want := "42.cname.yourservice.com"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRenewalGeneratingTimeoutDuration(t *testing.T) {
	Cfg.Renewal.GeneratingTimeout = "20m"
	if got := Cfg.Renewal.GeneratingTimeoutDuration(); got != 20*time.Minute {
		t.Fatalf("got %v, want 20m", got)
	}

	Cfg.Renewal.GeneratingTimeout = "not-a-duration"
	if got := Cfg.Renewal.GeneratingTimeoutDuration(); got != 15*time.Minute {
		t.Fatalf("invalid duration should fall back to 15m, got %v", got)
	}
}

func TestDecodeEncryptionKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEncryptionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
}

func TestValidateEncryptionKeyRequired(t *testing.T) {
	saved := Cfg
	t.Cleanup(func() { Cfg = saved })

	Cfg.DNS.AuthZone = "example.com"
	Cfg.DNS.Cloudflare.APIToken = "token"
	Cfg.Security.EncryptionKey = ""
	devFalse := false
	Cfg.Security.DevMode = &devFalse

	if err := Validate(); err == nil {
		t.Fatal("expected error without encryption key in production mode")
	}
}

func TestValidateAllowsMissingKeyInDevMode(t *testing.T) {
	saved := Cfg
	t.Cleanup(func() {
		Cfg = saved
		t.Setenv("CERTHUB_DEV", "")
	})

	Cfg.DNS.AuthZone = "example.com"
	Cfg.DNS.Cloudflare.APIToken = "token"
	Cfg.Security.EncryptionKey = ""
	devTrue := true
	Cfg.Security.DevMode = &devTrue
	t.Setenv("CERTHUB_DEV", "")

	if err := Validate(); err != nil {
		t.Fatalf("dev mode should allow missing encryption key: %v", err)
	}
}

func setValidProductionCfg(t *testing.T) {
	t.Helper()
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	devFalse := false
	Cfg.DNS.AuthZone = "example.com"
	Cfg.DNS.Cloudflare.APIToken = "token"
	Cfg.Security.EncryptionKey = key
	Cfg.Security.DevMode = &devFalse
	Cfg.Session.Secret = "unique-production-session-secret"
	Cfg.Server.AllowedOrigins = []string{"https://app.example.com"}
}

func TestValidateRequiresSessionSecretInProduction(t *testing.T) {
	saved := Cfg
	t.Cleanup(func() { Cfg = saved })

	setValidProductionCfg(t)
	Cfg.Session.Secret = defaultSessionSecret

	if err := Validate(); err == nil {
		t.Fatal("expected error for default session secret in production mode")
	}
}

func TestValidateRequiresAllowedOriginsInProduction(t *testing.T) {
	saved := Cfg
	t.Cleanup(func() { Cfg = saved })

	setValidProductionCfg(t)
	Cfg.Server.AllowedOrigins = nil

	if err := Validate(); err == nil {
		t.Fatal("expected error for missing allowed_origins in production mode")
	}
}

func TestValidateRejectsWildcardOriginInProduction(t *testing.T) {
	saved := Cfg
	t.Cleanup(func() { Cfg = saved })

	setValidProductionCfg(t)
	Cfg.Server.AllowedOrigins = []string{"*"}

	if err := Validate(); err == nil {
		t.Fatal("expected error for wildcard allowed_origins in production mode")
	}
}
