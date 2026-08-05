package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const platformVaults = `{"vaults":[
	{"vaultId":"1","name":"default-but-inactive","isDefault":true,"isActive":false,"connection":{"url":"https://inactive.example.com"}},
	{"vaultId":"2","name":"active-but-not-default","isDefault":false,"isActive":true,"connection":{"url":"https://not-default.example.com"}},
	{"vaultId":"3","name":"default-and-active","isDefault":true,"isActive":true,"connection":{"url":"https://vault.example.com"}}
]}`

// platformServer stands up a Platform (not a Secret Server): its Secret Server health
// check reports unhealthy, its Platform health check reports healthy, and it serves the
// headless token and vault-broker endpoints.
func platformServer(t *testing.T, vaults string) (*httptest.Server, *Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			fmt.Fprint(w, `{"healthy":false}`)
		case strings.HasSuffix(r.URL.Path, "/health"):
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/identity/api/oauth2/token/xpmplatform"):
			fmt.Fprint(w, `{"access_token":"platform-token","token_type":"Bearer","expires_in":3600}`)
		case strings.HasSuffix(r.URL.Path, "/vaultbroker/api/vaults"):
			fmt.Fprint(w, vaults)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	s, err := New(Configuration{
		ServerURL:         ts.URL,
		Credentials:       UserCredential{Username: "client-id", Password: "client-secret"},
		AllowedVaultHosts: []string{"vault.example.com"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return ts, s
}

// The selected vault URL becomes the host every later request — and the bearer token —
// is sent to, so the selection rule (default *and* active) is pinned here.
func TestCheckPlatformDetailsSelectsDefaultActiveVault(t *testing.T) {
	ts, s := platformServer(t, platformVaults)

	details, err := s.checkPlatformDetails(ts.URL)
	if err != nil {
		t.Fatalf("checkPlatformDetails returned error: %v", err)
	}
	if !details.isPlatform {
		t.Error("checkPlatformDetails did not identify the Platform")
	}
	if details.accessToken.value != "platform-token" {
		t.Errorf("token = %q, want %q", details.accessToken.value, "platform-token")
	}
	if s.ServerURL != "https://vault.example.com" {
		t.Errorf("ServerURL = %q, want the default and active vault %q", s.ServerURL, "https://vault.example.com")
	}
}

func TestCheckPlatformDetailsCachesPlatformToken(t *testing.T) {
	ts, s := platformServer(t, platformVaults)

	if _, err := s.checkPlatformDetails(ts.URL); err != nil {
		t.Fatalf("checkPlatformDetails returned error: %v", err)
	}

	cached, found := s.getCacheAccessToken(ts.URL)
	if !found {
		t.Fatal("expected the Platform token to be cached")
	}
	if cached != "platform-token" {
		t.Errorf("cached token = %q, want %q", cached, "platform-token")
	}
}

func TestCheckPlatformDetailsErrorsWhenNoVaultQualifies(t *testing.T) {
	const noQualifyingVault = `{"vaults":[
		{"vaultId":"1","isDefault":true,"isActive":false,"connection":{"url":"https://inactive.example.com"}},
		{"vaultId":"2","isDefault":false,"isActive":true,"connection":{"url":"https://not-default.example.com"}}
	]}`
	ts, s := platformServer(t, noQualifyingVault)
	before := s.ServerURL

	if _, err := s.checkPlatformDetails(ts.URL); err == nil {
		t.Error("expected an error when no vault is both default and active, got nil")
	}
	if s.ServerURL != before {
		t.Errorf("ServerURL = %q, want it left at %q when no vault qualifies", s.ServerURL, before)
	}
}

// Against a Platform, getAccessToken returns the token that Platform discovery
// produced rather than falling through to the Secret Server password grant.
func TestGetAccessTokenReturnsPlatformToken(t *testing.T) {
	_, s := platformServer(t, platformVaults)

	token, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("getAccessToken returned error: %v", err)
	}
	if token != "platform-token" {
		t.Errorf("token = %q, want the Platform token %q", token, "platform-token")
	}
}

// TestPlatformRejectedTokenIsEvicted is the regression for a Platform-only defect: the
// cached token is first used on the vault-broker call inside checkPlatformDetails, so a
// rejected token failed there and returned before accessResource's own eviction could
// run. The entry survived, was served again on every later call, and the client stayed
// broken for the token's whole lifetime. The eviction must key on the Platform base URL
// the token was cached under, not on the vault URL discovery rewrites ServerURL to.
func TestPlatformRejectedTokenIsEvicted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			fmt.Fprint(w, `{"healthy":false}`)
		case strings.HasSuffix(r.URL.Path, "/health"):
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/vaultbroker/api/vaults"):
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Username: "client-id", Password: "client-secret"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := s.setCacheAccessToken("rejected-token", 3600, ts.URL); err != nil {
		t.Fatalf("seeding the cache: %v", err)
	}

	if _, err := s.checkPlatformDetails(ts.URL); err == nil {
		t.Error("expected an error when the Platform rejects the cached token")
	}

	if _, found := s.getCacheAccessToken(ts.URL); found {
		t.Error("the rejected token survived in the cache; a later call would replay it")
	}
}

// TestClearTokenCacheForUsesGivenURL pins the key the eviction acts on, independent of
// any later rewrite of ServerURL.
func TestClearTokenCacheForUsesGivenURL(t *testing.T) {
	const platformURL = "https://platform.example.com"
	s, err := New(Configuration{ServerURL: platformURL, Credentials: UserCredential{Username: "kim"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := s.setCacheAccessToken("tok", 3600, platformURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}

	// Discovery rewrites ServerURL to the vault; clearing by the current base URL now
	// targets the wrong key, which is the defect this guards.
	s.ServerURL = "https://vault.example.com"
	s.clearTokenCache()
	if _, found := s.getCacheAccessToken(platformURL); !found {
		t.Fatal("test premise broken: clearing by the rewritten URL should miss")
	}

	s.clearTokenCacheFor(platformURL)
	if _, found := s.getCacheAccessToken(platformURL); found {
		t.Error("clearTokenCacheFor did not evict the entry for the URL it was given")
	}
}

// A caller-supplied Token is used as-is: no health probe, no grant request, no cache.
func TestGetAccessTokenUsesSuppliedTokenWithoutRequests(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "supplied-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	token, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("getAccessToken returned error: %v", err)
	}
	if token != "supplied-token" {
		t.Errorf("token = %q, want %q", token, "supplied-token")
	}
	if requests != 0 {
		t.Errorf("expected no HTTP request when a Token is supplied, got %d", requests)
	}
}
