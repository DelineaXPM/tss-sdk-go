package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
			body, _ := io.ReadAll(r.Body)
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

func TestConcurrentColdCacheUsesOneGrant(t *testing.T) {
	const callers = 32
	var mu sync.Mutex
	healthChecks := 0
	grantRequests := 0
	allProbed := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			mu.Lock()
			healthChecks++
			if healthChecks == callers {
				close(allProbed)
			}
			mu.Unlock()
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			mu.Lock()
			grantRequests++
			mu.Unlock()
			<-allProbed
			fmt.Fprint(w, `{"access_token":"shared-token","token_type":"bearer","expires_in":3600}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Username: "concurrent", Password: "pw"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		serverCopy := *s
		go func() {
			<-start
			token, err := serverCopy.getAccessToken()
			if err == nil && token != "shared-token" {
				err = fmt.Errorf("token = %q, want shared-token", token)
			}
			results <- err
		}()
	}
	close(start)
	for i := 0; i < callers; i++ {
		if err := <-results; err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if grantRequests != 1 {
		t.Errorf("grant requests = %d, want 1", grantRequests)
	}
}

func TestFailedGrantWakesWaitersAndNextCallRetries(t *testing.T) {
	const callers = 16
	var mu sync.Mutex
	healthChecks := 0
	grantRequests := 0
	allProbed := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck"):
			mu.Lock()
			healthChecks++
			if healthChecks == callers {
				close(allProbed)
			}
			mu.Unlock()
			fmt.Fprint(w, `{"healthy":true}`)
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			mu.Lock()
			grantRequests++
			requestNumber := grantRequests
			mu.Unlock()
			if requestNumber == 1 {
				<-allProbed
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, "temporary grant failure")
				return
			}
			fmt.Fprint(w, `{"access_token":"recovered-token","token_type":"bearer","expires_in":3600}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Username: "waiters", Password: "pw"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	results := make(chan error, callers)
	for range callers {
		serverCopy := *s
		go func() {
			_, err := serverCopy.getAccessToken()
			results <- err
		}()
	}
	var firstMessage string
	failures := 0
	for i := 0; i < callers; i++ {
		err := <-results
		if err == nil {
			// A caller scheduled after the failed flight was removed may legitimately
			// join the single recovery flight instead of observing the earlier error.
			continue
		}
		failures++
		if firstMessage == "" {
			firstMessage = err.Error()
		} else if err.Error() != firstMessage {
			t.Errorf("caller %d error = %q, want shared %q", i, err, firstMessage)
		}
	}
	if failures == 0 {
		t.Fatal("no caller observed the failed grant")
	}
	mu.Lock()
	if grantRequests < 1 || grantRequests > 2 {
		t.Errorf("concurrent batch made %d grants, want one failure and at most one recovery", grantRequests)
	}
	mu.Unlock()

	if token, err := s.getAccessToken(); err != nil || token != "recovered-token" {
		t.Fatalf("call after failed flight = (%q, %v), want recovered-token", token, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if grantRequests != 2 {
		t.Errorf("grant requests after recovery = %d, want 2", grantRequests)
	}
}

func TestDifferentTokenKeysGrantConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/v1/healthcheck") {
			fmt.Fprint(w, `{"healthy":true}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/oauth2/token") {
			started <- struct{}{}
			<-release
			fmt.Fprint(w, `{"access_token":"token","token_type":"bearer","expires_in":3600}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	servers := make([]*Server, 2)
	for i := range servers {
		var err error
		servers[i], err = New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Username: fmt.Sprintf("user-%d", i), Password: "pw"}})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
	}
	done := make(chan error, 2)
	for _, s := range servers {
		go func(s *Server) {
			_, err := s.getAccessToken()
			done <- err
		}(s)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("different cache keys serialized their token grants")
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("grant returned error: %v", err)
		}
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
