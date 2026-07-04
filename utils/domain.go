package utils

import (
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const maxDomainLength = 253
const maxLabelLength = 63

// NormalizeDomain lowercases and trims a domain for storage lookups.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ValidateDomainName checks FQDN format and returns a punycode-normalized ASCII name.
func ValidateDomainName(raw string) (string, error) {
	domain := NormalizeDomain(raw)
	if domain == "" {
		return "", fmt.Errorf("domain name is required")
	}
	if strings.ContainsAny(domain, " \t\r\n") {
		return "", fmt.Errorf("domain name must not contain spaces")
	}
	if strings.Contains(domain, "*") {
		return "", fmt.Errorf("wildcard domains are not supported")
	}
	if strings.ContainsAny(domain, ":/@") {
		return "", fmt.Errorf("invalid domain name")
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain name")
	}
	domain = strings.ToLower(ascii)

	if net.ParseIP(domain) != nil {
		return "", fmt.Errorf("IP addresses are not supported")
	}
	if len(domain) > maxDomainLength {
		return "", fmt.Errorf("domain name is too long")
	}
	if err := validateDomainLabels(domain); err != nil {
		return "", err
	}
	return domain, nil
}

func validateDomainLabels(domain string) error {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain must contain at least one dot (e.g. example.com)")
	}
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("domain name contains empty label")
	}
	if len(label) > maxLabelLength {
		return fmt.Errorf("domain label is too long")
	}
	if !utf8.ValidString(label) {
		return fmt.Errorf("invalid domain label")
	}
	for i, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(label)-1 {
				return fmt.Errorf("domain labels must not start or end with hyphen")
			}
		default:
			return fmt.Errorf("domain labels may only contain letters, digits, and hyphens")
		}
	}
	return nil
}
