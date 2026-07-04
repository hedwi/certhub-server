package utils

import "testing"

func TestValidateDomainName(t *testing.T) {
	valid := map[string]string{
		"example.com":     "example.com",
		"www.example.com": "www.example.com",
		"EXAMPLE.COM.":    "example.com",
		" münchen.de ":    "xn--mnchen-3ya.de",
	}
	for input, want := range valid {
		got, err := ValidateDomainName(input)
		if err != nil {
			t.Fatalf("ValidateDomainName(%q): unexpected error: %v", input, err)
		}
		if got != want {
			t.Fatalf("ValidateDomainName(%q) = %q, want %q", input, got, want)
		}
	}

	invalid := []string{
		"",
		" ",
		"*example.com",
		"*.example.com",
		"example com",
		"http://example.com",
		"example.com/path",
		"127.0.0.1",
		"localhost",
		"-bad.example.com",
		"bad-.example.com",
		"exam_ple.com",
	}
	for _, input := range invalid {
		if _, err := ValidateDomainName(input); err == nil {
			t.Fatalf("ValidateDomainName(%q): expected error", input)
		}
	}
}
