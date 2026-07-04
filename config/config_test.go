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

func TestUnclaimedErrorReleaseDuration(t *testing.T) {
	Cfg.Domain.UnclaimedErrorRelease = "48h"
	if got := Cfg.Domain.UnclaimedErrorReleaseDuration(); got != 48*time.Hour {
		t.Fatalf("got %v, want 48h", got)
	}

	Cfg.Domain.UnclaimedErrorRelease = ""
	if got := Cfg.Domain.UnclaimedErrorReleaseDuration(); got != 72*time.Hour {
		t.Fatalf("empty should default to 72h, got %v", got)
	}
}

func TestRegistrationDisabledByDefault(t *testing.T) {
	var auth AuthConfig
	if auth.IsRegistrationEnabled() {
		t.Fatal("registration should be disabled by default")
	}

	enabled := true
	auth.RegistrationEnabled = &enabled
	if !auth.IsRegistrationEnabled() {
		t.Fatal("registration should be enabled when configured true")
	}
}

func TestDNSPropagationDuration(t *testing.T) {
	Cfg.DNS.PropagationTimeout = "10m"
	if got := Cfg.DNS.PropagationTimeoutDuration(); got != 10*time.Minute {
		t.Fatalf("got %v, want 10m", got)
	}

	Cfg.DNS.PropagationTimeout = "not-a-duration"
	if got := Cfg.DNS.PropagationTimeoutDuration(); got != 5*time.Minute {
		t.Fatalf("invalid timeout should fall back to 5m, got %v", got)
	}

	Cfg.DNS.PropagationInterval = "5s"
	if got := Cfg.DNS.PropagationIntervalDuration(); got != 5*time.Second {
		t.Fatalf("got %v, want 5s", got)
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

func TestMaxConcurrentCertJobs(t *testing.T) {
	Cfg.Renewal.MaxConcurrentJobs = 3
	if got := Cfg.Renewal.MaxConcurrentCertJobs(); got != 3 {
		t.Fatalf("got %d, want 3", got)
	}

	Cfg.Renewal.MaxConcurrentJobs = 0
	if got := Cfg.Renewal.MaxConcurrentCertJobs(); got != 5 {
		t.Fatalf("zero should fall back to 5, got %d", got)
	}
}

func TestCertIssueRequestsPerHour(t *testing.T) {
	Cfg.RateLimit.CertIssuePerHour = 0
	if got := Cfg.RateLimit.CertIssueRequestsPerHour(); got != 10 {
		t.Fatalf("unset should default to 10, got %d", got)
	}

	Cfg.RateLimit.CertIssuePerHour = 5
	if got := Cfg.RateLimit.CertIssueRequestsPerHour(); got != 5 {
		t.Fatalf("got %d, want 5", got)
	}

	Cfg.RateLimit.CertIssuePerHour = -1
	if got := Cfg.RateLimit.CertIssueRequestsPerHour(); got != 0 {
		t.Fatalf("disabled should return 0, got %d", got)
	}
	if Cfg.RateLimit.CertIssueRateLimitEnabled() {
		t.Fatal("expected cert issue rate limit to be disabled at -1")
	}
}

func TestAutoRenewBackoffDuration(t *testing.T) {
	Cfg.Renewal.RenewBackoffBase = "6h"
	Cfg.Renewal.RenewBackoffMax = "72h"

	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 6 * time.Hour},
		{2, 12 * time.Hour},
		{3, 24 * time.Hour},
		{4, 48 * time.Hour},
		{5, 72 * time.Hour},
		{10, 72 * time.Hour},
	}
	for _, tc := range cases {
		if got := Cfg.Renewal.AutoRenewBackoffDuration(tc.failures); got != tc.want {
			t.Fatalf("failures=%d: got %v, want %v", tc.failures, got, tc.want)
		}
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
