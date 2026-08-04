package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// grantFixture stands up a Secret Server that reports healthy and issues password
// grants, recording every token request.
func grantFixture(t *testing.T, credentials UserCredential) (*Server, *[]url.Values, *int) {
	t.Helper()
	var grants []url.Values
	tokenRequests := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			tokenRequests++
			body, _ := ioutil.ReadAll(r.Body)
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Errorf("unparseable grant body %q: %v", body, err)
			}
			grants = append(grants, values)
			fmt.Fprint(w, `{"access_token":"granted-token","token_type":"bearer","expires_in":3600}`)
		default:
			fmt.Fprint(w, `{}`)
		}
	}))
	t.Cleanup(ts.Close)

	s, err := New(Configuration{ServerURL: ts.URL, Credentials: credentials})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return s, &grants, &tokenRequests
}

// The password grant is where the caller's credentials go on the wire; its shape is
// pinned here.
func TestGetAccessTokenPasswordGrant(t *testing.T) {
	s, grants, _ := grantFixture(t, UserCredential{Username: "grace", Password: "pw"})

	token, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("getAccessToken returned error: %v", err)
	}
	if token != "granted-token" {
		t.Errorf("token = %q, want %q", token, "granted-token")
	}
	if len(*grants) != 1 {
		t.Fatalf("recorded %d grant requests, want 1", len(*grants))
	}

	values := (*grants)[0]
	for field, want := range map[string]string{
		"username":   "grace",
		"password":   "pw",
		"grant_type": "password",
	} {
		if got := values.Get(field); got != want {
			t.Errorf("grant %s = %q, want %q", field, got, want)
		}
	}
	if _, present := values["domain"]; present {
		t.Error("grant carried a domain field for a credential with no Domain")
	}
}

func TestGetAccessTokenPasswordGrantIncludesDomain(t *testing.T) {
	s, grants, _ := grantFixture(t, UserCredential{Domain: "corp.example.com", Username: "grace", Password: "pw"})

	if _, err := s.getAccessToken(); err != nil {
		t.Fatalf("getAccessToken returned error: %v", err)
	}
	if got := (*grants)[0].Get("domain"); got != "corp.example.com" {
		t.Errorf("grant domain = %q, want %q", got, "corp.example.com")
	}
}

// A second call must be served from the cache rather than re-sending the credentials.
func TestGetAccessTokenReusesCachedToken(t *testing.T) {
	s, _, tokenRequests := grantFixture(t, UserCredential{Username: "heidi", Password: "pw"})

	first, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("first getAccessToken returned error: %v", err)
	}
	second, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("second getAccessToken returned error: %v", err)
	}

	if first != second {
		t.Errorf("second token = %q, want the cached %q", second, first)
	}
	if *tokenRequests != 1 {
		t.Errorf("sent %d grant requests, want 1 (the second call should hit the cache)", *tokenRequests)
	}
}

// TestGetAccessTokenRefreshesAfterComputedExpiry exercises the cached-lifetime formula
// end to end: the moment it computes must be what decides reuse versus refresh. Other
// tests assert the arithmetic directly, or seed the cache with a lifetime of 0 or an
// hour; none let a server-supplied expires_in flow through the formula and then observe
// the refresh it schedules.
//
// A 2-second grant is cached for int(math.Floor(2*0.9)) = 1 second, so a call after that
// must obtain a second token instead of replaying the first.
// TestTokenCacheRetainedForMostOfLifetime pins the arithmetic; this pins that the value
// it computes is what actually governs reuse.
//
// It sleeps, deliberately: nothing short of real elapsed time exercises the comparison
// against the value the formula stored.
func TestGetAccessTokenRefreshesAfterComputedExpiry(t *testing.T) {
	issued := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			issued++
			fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"bearer","expires_in":2}`, issued)
		default:
			fmt.Fprint(w, `{}`)
		}
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Username: "judy", Password: "pw"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	first, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("first getAccessToken returned error: %v", err)
	}
	if issued != 1 {
		t.Fatalf("grants issued = %d, want 1", issued)
	}

	time.Sleep(1500 * time.Millisecond)

	second, err := s.getAccessToken()
	if err != nil {
		t.Fatalf("getAccessToken after expiry returned error: %v", err)
	}
	if second == first {
		t.Error("the cached token was replayed past the lifetime the formula computed")
	}
	if issued != 2 {
		t.Errorf("grants issued = %d, want 2 (the expired entry should force one refresh)", issued)
	}

	// The refreshed token must be the one now cached, not the stale value.
	if cached, found := s.getCacheAccessToken(ts.URL); !found || cached != second {
		t.Errorf("cached token = (%q, %v), want the refreshed %q", cached, found, second)
	}
}

// A grant response that is not JSON must surface as an error, not a token.
func TestGetAccessTokenRejectsUnparseableGrant(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck") {
			fmt.Fprint(w, `{"healthy":true}`)
			return
		}
		fmt.Fprint(w, "not json")
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Username: "ivan", Password: "pw"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	token, err := s.getAccessToken()
	if err == nil {
		t.Error("expected an error for an unparseable grant response, got nil")
	}
	if token != "" {
		t.Errorf("token = %q, want empty on a failed grant", token)
	}
}
