package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

const dnsVerifyTimeout = 15 * time.Second

// VerifyChallengeCNAME checks that _acme-challenge.{domain} CNAME points to the expected delegation target.
func VerifyChallengeCNAME(ctx context.Context, domain, expectedTarget string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, dnsVerifyTimeout)
	defer cancel()

	challengeHost := "_acme-challenge." + strings.TrimSuffix(domain, ".")
	expected := strings.TrimSuffix(strings.ToLower(expectedTarget), ".")

	resolver := net.Resolver{}
	cname, err := resolver.LookupCNAME(ctx, challengeHost)
	if err != nil {
		return fmt.Errorf("CNAME lookup failed for %s: %w", challengeHost, err)
	}

	actual := strings.TrimSuffix(strings.ToLower(cname), ".")
	if actual != expected {
		return fmt.Errorf("CNAME mismatch for %s: got %q, expected %q", challengeHost, actual, expected)
	}
	return nil
}

// ParseCertExpiry extracts NotAfter from the first PEM certificate block.
func ParseCertExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}
