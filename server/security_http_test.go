package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientRejectsCrossOriginRedirect(t *testing.T) {
	reachedTarget := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedTarget = true
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	s, err := New(Configuration{ServerURL: source.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := s.client().Get(source.URL); err == nil {
		t.Fatal("cross-origin redirect was followed")
	}
	if reachedTarget {
		t.Error("redirect target received a request")
	}
}

func TestCredentialGrantDoesNotFollowRedirect(t *testing.T) {
	for _, product := range []string{"SecretServer", "Platform"} {
		for _, status := range []int{
			http.StatusMovedPermanently,
			http.StatusFound,
			http.StatusSeeOther,
			http.StatusTemporaryRedirect,
			http.StatusPermanentRedirect,
		} {
			t.Run(fmt.Sprintf("%s/%d", product, status), func(t *testing.T) {
				stolenRequests := 0
				var ts *httptest.Server
				ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/v1/healthcheck":
						fmt.Fprintf(w, `{"healthy":%t}`, product == "SecretServer")
					case "/health":
						fmt.Fprint(w, `{"healthy":true}`)
					case "/oauth2/token", "/identity/api/oauth2/token/xpmplatform":
						http.Redirect(w, r, ts.URL+"/stolen", status)
					case "/stolen":
						stolenRequests++
					default:
						http.NotFound(w, r)
					}
				}))
				defer ts.Close()

				s, err := New(Configuration{
					ServerURL:   ts.URL,
					Credentials: UserCredential{Username: "user", Password: "secret"},
				})
				if err != nil {
					t.Fatalf("New returned error: %v", err)
				}
				if _, err := s.getAccessToken(); err == nil {
					t.Fatal("redirecting token endpoint returned no error")
				}
				if stolenRequests != 0 {
					t.Errorf("credential-bearing redirect was followed %d times", stolenRequests)
				}
			})
		}
	}
}

func TestTokenGrantRequiresAccessTokenAndExpiry(t *testing.T) {
	for _, body := range []string{
		`{"token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"token","token_type":"Bearer","expires_in":0}`,
		`{"access_token":"token","token_type":"Bearer","expires_in":-1}`,
		fmt.Sprintf(`{"access_token":"token","token_type":"Bearer","expires_in":%d}`, maxOAuthTokenLifetimeSeconds+1),
		`{"access_token":"token","token_type":"MAC","expires_in":3600}`,
		`{"access_token":"token\nforged","token_type":"Bearer","expires_in":3600}`,
	} {
		t.Run(body, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/healthcheck") {
					fmt.Fprint(w, `{"healthy":true}`)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer ts.Close()

			s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Username: "u", Password: "p"}})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}
			if token, err := s.getAccessToken(); err == nil {
				t.Fatalf("invalid grant returned token %q without an error", token)
			}
		})
	}
}

func TestPlatformTokenGrantIsValidatedBeforeVaultRequest(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"access_token":"token","token_type":"Bearer","expires_in":0}`,
		`{"access_token":"token","token_type":"MAC","expires_in":3600}`,
		fmt.Sprintf(`{"access_token":"token","token_type":"Bearer","expires_in":%d}`, maxOAuthTokenLifetimeSeconds+1),
	} {
		t.Run(body, func(t *testing.T) {
			vaultRequests := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
					fmt.Fprint(w, `{"healthy":false}`)
				case strings.HasSuffix(r.URL.Path, "/health"):
					fmt.Fprint(w, `{"healthy":true}`)
				case strings.HasSuffix(r.URL.Path, "/identity/api/oauth2/token/xpmplatform"):
					fmt.Fprint(w, body)
				case strings.HasSuffix(r.URL.Path, "/vaultbroker/api/vaults"):
					vaultRequests++
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()
			s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Username: "client", Password: "secret"}})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}
			if token, err := s.getAccessToken(); err == nil {
				t.Fatalf("invalid Platform grant returned token %q", token)
			}
			if vaultRequests != 0 {
				t.Errorf("vault broker received %d requests after an invalid token grant", vaultRequests)
			}
		})
	}
}

func TestHealthRequiresSuccessStatusAndExactBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "non-2xx", status: http.StatusInternalServerError, body: "Healthy"},
		{name: "substring", status: http.StatusOK, body: "service is not Healthy today"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer ts.Close()
			s, err := New(Configuration{ServerURL: ts.URL})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}
			healthy, err := s.checkJSONResponse(ts.URL)
			if healthy || err == nil {
				t.Fatalf("checkJSONResponse = (%v, %v), want unhealthy error", healthy, err)
			}
			if tc.status != http.StatusOK {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != tc.status {
					t.Errorf("error = %v, want wrapped HTTPError status %d", err, tc.status)
				}
			}
		})
	}
}

func TestPlatformRejectsUntrustedVaultURL(t *testing.T) {
	for _, vaultURL := range []string{
		"://not-a-url",
		"http://vault.example.com",
		"https://attacker.example.net",
		"https://user:password@vault.example.com",
		"https://vault.example.com?redirect=attacker",
	} {
		t.Run(vaultURL, func(t *testing.T) {
			vaults := fmt.Sprintf(`{"vaults":[{"isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, vaultURL)
			ts, s := platformServer(t, vaults)
			s.AllowedVaultHosts = nil
			before := s.ServerURL
			if _, err := s.checkPlatformDetails(ts.URL); err == nil {
				t.Fatal("untrusted vault URL was accepted")
			}
			if s.ServerURL != before {
				t.Errorf("ServerURL changed to rejected URL %q", s.ServerURL)
			}
		})
	}
}

func TestPlatformAcceptsOnlyExplicitVaultTrustRelationships(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://platform.example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := s.validateDiscoveredVaultURL(s.ServerURL, "https://tenant.secretservercloud.com/SecretServer"); err != nil {
		t.Errorf("official cloud vault was rejected: %v", err)
	}

	s.AllowedVaultHosts = []string{"vault.internal.example"}
	if _, err := s.validateDiscoveredVaultURL(s.ServerURL, "https://vault.internal.example/SecretServer"); err != nil {
		t.Errorf("explicitly allowed on-premises vault was rejected: %v", err)
	}

	s.AllowedVaultHosts = nil
	s.VaultURLValidator = func(platformURL, vaultURL *url.URL) error {
		vaultURL.Scheme = "http" // Mutation must not weaken the invariant or returned URL.
		return nil
	}
	accepted, err := s.validateDiscoveredVaultURL(s.ServerURL, "https://custom.internal.example/SecretServer")
	if err != nil {
		t.Fatalf("custom validator approval was rejected: %v", err)
	}
	if accepted.Scheme != "https" {
		t.Errorf("validator mutated the accepted URL scheme to %q", accepted.Scheme)
	}
}

func TestRejectedPlatformVaultReceivesNoBearerToken(t *testing.T) {
	vaultRequests := 0
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultRequests++
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("rejected vault received Authorization %q", authorization)
		}
	}))
	defer vault.Close()

	vaults := fmt.Sprintf(`{"vaults":[{"isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, vault.URL)
	_, s := platformServer(t, vaults)
	s.AllowedVaultHosts = nil
	if _, err := s.getAccessToken(); err == nil {
		t.Fatal("plaintext vault URL was accepted")
	}
	if vaultRequests != 0 {
		t.Errorf("rejected vault received %d requests", vaultRequests)
	}
}
