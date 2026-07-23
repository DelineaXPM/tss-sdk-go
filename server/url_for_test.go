package server

import (
	"net/url"
	"strings"
	"testing"
)

// urlFor decides which host every credentialed request is sent to, so its branches are
// pinned here: Secret Server Cloud tenant vs. explicit ServerURL, and the token endpoint
// vs. an API resource.
func TestUrlForWithServerURL(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://secrets.example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	for _, c := range []struct {
		resource, path, want string
	}{
		{"secrets", "1", "https://secrets.example.com/api/v1/secrets/1"},
		{"secret-templates", "3", "https://secrets.example.com/api/v1/secret-templates/3"},
		{"token", "", "https://secrets.example.com/oauth2/token"},
	} {
		if got := s.urlFor(c.resource, c.path); got != c.want {
			t.Errorf("urlFor(%q, %q) = %q, want %q", c.resource, c.path, got, c.want)
		}
	}
}

func TestUrlForTrimsTrailingSlashOnServerURL(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://secrets.example.com/"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	want := "https://secrets.example.com/api/v1/secrets/1"
	if got := s.urlFor("secrets", "1"); got != want {
		t.Errorf("urlFor = %q, want %q", got, want)
	}
}

func TestUrlForWithCloudTenant(t *testing.T) {
	for _, c := range []struct {
		tenant, tld, want string
	}{
		{"acme", "", "https://acme.secretservercloud.com/api/v1/secrets/1"},
		{"acme", "eu", "https://acme.secretservercloud.eu/api/v1/secrets/1"},
		{"acme", "com.au", "https://acme.secretservercloud.com.au/api/v1/secrets/1"},
	} {
		s, err := New(Configuration{Tenant: c.tenant, TLD: c.tld})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		if got := s.urlFor("secrets", "1"); got != c.want {
			t.Errorf("tenant %q tld %q: urlFor = %q, want %q", c.tenant, c.tld, got, c.want)
		}
	}
}

// baseURL is the single derivation every request path depends on, so both of its
// branches are asserted directly.
func TestBaseURL(t *testing.T) {
	for _, c := range []struct {
		name   string
		config Configuration
		want   string
	}{
		{"explicit ServerURL", Configuration{ServerURL: "https://secrets.example.com"}, "https://secrets.example.com"},
		{"cloud tenant", Configuration{Tenant: "acme"}, "https://acme.secretservercloud.com/"},
		{"cloud tenant with TLD", Configuration{Tenant: "acme", TLD: "eu"}, "https://acme.secretservercloud.eu/"},
	} {
		s, err := New(c.config)
		if err != nil {
			t.Fatalf("%s: New returned error: %v", c.name, err)
		}
		if got := s.baseURL(); got != c.want {
			t.Errorf("%s: baseURL = %q, want %q", c.name, got, c.want)
		}
	}
}

// The search URL must be built from the cloud host too, not only from an explicit
// ServerURL.
func TestUrlForSearchWithCloudTenant(t *testing.T) {
	s, err := New(Configuration{Tenant: "acme"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	raw := s.urlForSearch("secrets", "term", "")
	if !strings.HasPrefix(raw, "https://acme.secretservercloud.com/api/v1/secrets?") {
		t.Errorf("urlForSearch = %q, want it built from the cloud tenant host", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("unparseable URL %q: %v", raw, err)
	}
	if got := u.Query().Get("paging.filter.searchText"); got != "term" {
		t.Errorf("searchText = %q, want %q", got, "term")
	}
}

func TestUrlForSearchRejectsUnknownResource(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://secrets.example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if got := s.urlForSearch("secret-templates", "term", ""); got != "" {
		t.Errorf("urlForSearch for an unsupported resource = %q, want an empty string", got)
	}
}
