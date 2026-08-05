package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAccessResourceReturnsErrorOnTransportError guards against the nil *http.Response
// dereference in accessResource: on a transport error (here a Timeout-induced context
// deadline) handleResponse returns a nil response, so accessResource must return an
// error rather than panic on statusCode.StatusCode. Without the nil guard this test
// panics instead of failing cleanly.
func TestAccessResourceReturnsErrorOnTransportError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
		Timeout:     20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	data, err := s.accessResource("GET", "secrets", "1", nil)
	if err == nil {
		t.Fatal("expected a transport/timeout error, got nil")
	}
	if data != nil {
		t.Errorf("expected nil data on transport error, got %q", data)
	}
}

// TestAccessResourceClearsTokenCacheOnAuthFailure pins the eviction that makes the
// cached-token lifetime safe: when the server rejects a request with 401 or 403, the
// cached token is dropped so the next call re-authenticates rather than replaying a
// token the server no longer honors.
func TestAccessResourceClearsTokenCacheOnAuthFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/healthcheck") {
				fmt.Fprint(w, `{"healthy":true}`)
				return
			}
			w.WriteHeader(status)
		}))

		s, err := New(Configuration{
			ServerURL:   ts.URL,
			Credentials: UserCredential{Username: "frank", Password: "pw"},
		})
		if err != nil {
			ts.Close()
			t.Fatalf("New returned error: %v", err)
		}

		if err := s.setCacheAccessToken("cached-token", 3600, ts.URL); err != nil {
			ts.Close()
			t.Fatalf("setCacheAccessToken returned error: %v", err)
		}

		if _, err := s.accessResource("GET", "secrets", "1", nil); err == nil {
			t.Errorf("status %d: expected an error from the rejected request, got nil", status)
		}

		if _, found := s.getCacheAccessToken(ts.URL); found {
			t.Errorf("status %d: cached token survived an auth failure; it must be evicted", status)
		}
		ts.Close()
	}
}

// The eviction must hold on every request path that presents the cached token, not only
// accessResource: a token the server rejected during a search or a file upload was
// previously replayed until a plain API call happened to evict it.
func TestSearchAndUploadClearTokenCacheOnAuthFailure(t *testing.T) {
	for _, op := range []struct {
		name string
		call func(s *Server) error
	}{
		{"search", func(s *Server) error {
			_, err := s.searchResources("secrets", "term", "")
			return err
		}},
		{"upload", func(s *Server) error {
			return s.uploadFile(1, SecretField{Slug: "attachment", Filename: "f.txt", ItemValue: "data"})
		}},
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/healthcheck") {
				fmt.Fprint(w, `{"healthy":true}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))

		s, err := New(Configuration{
			ServerURL:   ts.URL,
			Credentials: UserCredential{Username: "frank", Password: "pw"},
		})
		if err != nil {
			ts.Close()
			t.Fatalf("%s: New returned error: %v", op.name, err)
		}

		if err := s.setCacheAccessToken("cached-token", 3600, ts.URL); err != nil {
			ts.Close()
			t.Fatalf("%s: setCacheAccessToken returned error: %v", op.name, err)
		}

		if err := op.call(s); err == nil {
			t.Errorf("%s: expected an error from the rejected request, got nil", op.name)
		}

		if _, found := s.getCacheAccessToken(ts.URL); found {
			t.Errorf("%s: cached token survived an auth failure; it must be evicted", op.name)
		}
		ts.Close()
	}
}

// TestAccessResourceRejectsUnknownResource verifies the resource allowlist: only the
// secrets and secret-templates resources may be addressed, so a caller cannot steer a
// credentialed request at an arbitrary API path. The rejection must happen before any
// request is sent.
func TestAccessResourceRejectsUnknownResource(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := s.accessResource("GET", "users", "1", nil); err == nil {
		t.Error("accessResource accepted an unknown resource, want an error")
	}
	if _, err := s.accessResource("GET", "../../admin", "1", nil); err == nil {
		t.Error("accessResource accepted a path-traversal resource, want an error")
	}
	// searchResources is narrower still: it allows only secrets.
	if _, err := s.searchResources("secret-templates", "term", ""); err == nil {
		t.Error("searchResources accepted a resource other than secrets, want an error")
	}

	if requests != 0 {
		t.Errorf("expected no HTTP request for a rejected resource, got %d", requests)
	}
}

// A request that cannot be constructed — a malformed ServerURL, or a method containing
// characters HTTP does not allow — must return an error rather than panic.
func TestAccessResourceReturnsErrorOnUnbuildableRequest(t *testing.T) {
	valid, err := New(Configuration{
		ServerURL:   "https://secrets.example.com",
		Credentials: UserCredential{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := valid.accessResource("BAD METHOD", "secrets", "1", nil); err == nil {
		t.Error("accessResource accepted an invalid HTTP method, want an error")
	}

	malformed, err := New(Configuration{
		ServerURL:   "://not-a-url",
		Credentials: UserCredential{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := malformed.accessResource("GET", "secrets", "1", nil); err == nil {
		t.Error("accessResource accepted a malformed ServerURL, want an error")
	}
	if _, err := malformed.searchResources("secrets", "term", ""); err == nil {
		t.Error("searchResources accepted a malformed ServerURL, want an error")
	}
}

// A request body that cannot be marshaled must surface as an error before any request
// is sent.
func TestAccessResourceReturnsErrorOnUnmarshalableInput(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	// A channel cannot be represented in JSON.
	if _, err := s.accessResource("POST", "secrets", "1", make(chan int)); err == nil {
		t.Error("accessResource accepted an unmarshalable body, want an error")
	}
	if requests != 0 {
		t.Errorf("expected no HTTP request when the body cannot be marshaled, got %d", requests)
	}
}
