package server

import (
	"net/http"
	"net/http/httptest"
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
