package config

import "testing"

func TestDelegationTarget(t *testing.T) {
	Cfg.Domain.CNameTarget = "cname.yourservice.com"
	got := DelegationTarget(42)
	want := "42.cname.yourservice.com"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
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
