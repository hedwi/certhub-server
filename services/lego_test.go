package services

import (
	"testing"

	"github.com/go-acme/lego/v4/lego"
	"github.com/hedwi/certhub-server/config"
)

func TestNormalizeCAURL(t *testing.T) {
	cases := map[string]string{
		"https://acme-v02.api.letsencrypt.org/directory":   "https://acme-v02.api.letsencrypt.org/directory",
		"https://acme-v02.api.letsencrypt.org/directory/":  "https://acme-v02.api.letsencrypt.org/directory",
		"  https://acme-staging-v02.api.letsencrypt.org/directory  ": "https://acme-staging-v02.api.letsencrypt.org/directory",
	}
	for input, want := range cases {
		if got := normalizeCAURL(input); got != want {
			t.Fatalf("normalizeCAURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEffectiveCAURL(t *testing.T) {
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.ACME.CAURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	if got := effectiveCAURL(); got != config.Cfg.ACME.CAURL {
		t.Fatalf("got %q, want configured staging URL", got)
	}

	config.Cfg.ACME.CAURL = ""
	if got := effectiveCAURL(); got != lego.LEDirectoryProduction {
		t.Fatalf("got %q, want production default", got)
	}
}
