package server

import "testing"

// New must accept exactly one of ServerURL and Tenant: neither leaves no host to talk
// to, and both would make the target ambiguous.
func TestNewRequiresExactlyOneTarget(t *testing.T) {
	if _, err := New(Configuration{}); err == nil {
		t.Error("New accepted a configuration with neither ServerURL nor Tenant, want an error")
	}
	if _, err := New(Configuration{ServerURL: "https://secrets.example.com", Tenant: "acme"}); err == nil {
		t.Error("New accepted a configuration with both ServerURL and Tenant, want an error")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	s, err := New(Configuration{Tenant: "acme"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if s.TLD != defaultTLD {
		t.Errorf("TLD = %q, want %q", s.TLD, defaultTLD)
	}
	if s.apiPathURI != "api/v1" {
		t.Errorf("apiPathURI = %q, want %q", s.apiPathURI, "api/v1")
	}
	if s.tokenPathURI != "oauth2/token" {
		t.Errorf("tokenPathURI = %q, want %q", s.tokenPathURI, "oauth2/token")
	}
}

func TestNewTrimsConfiguredPaths(t *testing.T) {
	s, err := New(Configuration{
		ServerURL:    "https://secrets.example.com",
		apiPathURI:   "/custom/api/",
		tokenPathURI: "/custom/token/",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if s.apiPathURI != "custom/api" {
		t.Errorf("apiPathURI = %q, want %q", s.apiPathURI, "custom/api")
	}
	if s.tokenPathURI != "custom/token" {
		t.Errorf("tokenPathURI = %q, want %q", s.tokenPathURI, "custom/token")
	}
	if got, want := s.urlFor("token", ""), "https://secrets.example.com/custom/token"; got != want {
		t.Errorf("urlFor(token) = %q, want %q", got, want)
	}
}
