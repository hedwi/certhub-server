package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	encryptionKey = []byte("01234567890123456789012345678901")
	t.Cleanup(func() { encryptionKey = nil })

	plain := []byte("secret private key material")
	encrypted, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(encrypted) == string(plain) {
		t.Fatal("expected ciphertext to differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(plain) {
		t.Fatalf("round-trip mismatch: got %q", decrypted)
	}
}

func TestEncryptNoKeyPassthrough(t *testing.T) {
	encryptionKey = nil
	data := []byte("plaintext")
	out, err := Encrypt(data)
	if err != nil || string(out) != "plaintext" {
		t.Fatalf("expected passthrough, got %q err=%v", out, err)
	}
}

func TestParseCertExpiry(t *testing.T) {
	notAfter := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got, err := ParseCertExpiry(pemBytes)
	if err != nil {
		t.Fatalf("ParseCertExpiry: %v", err)
	}
	if !got.Equal(notAfter) {
		t.Fatalf("expected %v, got %v", notAfter, got)
	}
}

func TestVerifyChallengeCNAME_InvalidDomain(t *testing.T) {
	err := VerifyChallengeCNAME(context.Background(), "definitely-not-a-real-domain-xyz123.invalid", "1.cname.example.com")
	if err == nil {
		t.Fatal("expected DNS lookup error")
	}
}
