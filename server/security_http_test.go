package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	stolenRequests := 0
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			http.Redirect(w, r, ts.URL+"/stolen", http.StatusTemporaryRedirect)
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
}

func TestTokenGrantRequiresAccessTokenAndExpiry(t *testing.T) {
	for _, body := range []string{
		`{"token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"token","token_type":"Bearer","expires_in":0}`,
		`{"access_token":"token","token_type":"MAC","expires_in":3600}`,
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
