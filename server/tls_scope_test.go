package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("stub round tripper")
}

func defaultTransportTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport is not an *http.Transport")
	}
	return transport.TLSClientConfig
}

// TestNewDoesNotMutateDefaultTransport is the core CWE-295 regression: a caller-supplied
// TLSClientConfig must be scoped to the Server and must never be written onto the
// process-global http.DefaultTransport.
func TestNewDoesNotMutateDefaultTransport(t *testing.T) {
	before := defaultTransportTLSConfig(t)

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	s, err := New(Configuration{ServerURL: "https://example.com", TLSClientConfig: tlsConfig})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if after := defaultTransportTLSConfig(t); after != before {
		t.Errorf("http.DefaultTransport.TLSClientConfig was mutated: got %p, want %p", after, before)
	}

	transport, ok := s.client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Server client transport is not an *http.Transport")
	}
	if transport == http.DefaultTransport {
		t.Error("Server transport is the shared http.DefaultTransport; expected a distinct clone")
	}
	if transport.TLSClientConfig != tlsConfig {
		t.Errorf("Server transport TLSClientConfig = %p, want %p", transport.TLSClientConfig, tlsConfig)
	}
}

// TestServerClientUsesSuppliedTLSConfig proves the per-Server client honors the supplied
// TLS config while the process-global default client is left with normal verification.
func TestServerClientUsesSuppliedTLSConfig(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	resp, err := s.client().Get(ts.URL)
	if err != nil {
		t.Fatalf("per-Server client request failed: %v", err)
	}
	resp.Body.Close()

	if _, err := http.DefaultClient.Get(ts.URL); err == nil {
		t.Error("http.DefaultClient accepted the test server's untrusted cert; global TLS verification was weakened")
	}
}

// TestNewNoPanicWhenDefaultTransportReplaced covers the unchecked type-assertion vector:
// New must not panic when http.DefaultTransport is not an *http.Transport.
func TestNewNoPanicWhenDefaultTransportReplaced(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = stubRoundTripper{}
	defer func() { http.DefaultTransport = original }()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	s, err := New(Configuration{ServerURL: "https://example.com", TLSClientConfig: tlsConfig})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	transport, ok := s.client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Server client transport is not an *http.Transport")
	}
	if transport.TLSClientConfig != tlsConfig {
		t.Errorf("Server transport TLSClientConfig = %p, want %p", transport.TLSClientConfig, tlsConfig)
	}
}

// TestServerRequestPathUsesPerServerClient proves an actual SDK request path (the
// checkJSONResponse health check, previously a free function using package-level
// http.Get) routes through the per-Server client: it succeeds against a self-signed
// httptest server only because the per-Server InsecureSkipVerify config is applied.
// If it silently fell back to http.DefaultClient the cert would be rejected.
func TestServerRequestPathUsesPerServerClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	healthy, err := s.checkJSONResponse(ts.URL)
	if err != nil {
		t.Fatalf("checkJSONResponse returned error: %v", err)
	}
	if !healthy {
		t.Error("checkJSONResponse failed; request did not use the per-Server TLS config")
	}
}

// TestPerServerTransportInheritsDefaultTuning verifies the per-Server transport copies
// http.DefaultTransport's connection tuning (ac-2) rather than starting bare.
func TestPerServerTransportInheritsDefaultTuning(t *testing.T) {
	src, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not an *http.Transport")
	}

	s, err := New(Configuration{ServerURL: "https://example.com", TLSClientConfig: &tls.Config{}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	transport, ok := s.client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Server client transport is not an *http.Transport")
	}

	if transport.Proxy == nil {
		t.Error("per-Server transport did not inherit Proxy from the default transport")
	}
	if transport.MaxIdleConns != src.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, src.MaxIdleConns)
	}
	if transport.IdleConnTimeout != src.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, src.IdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout != src.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, src.TLSHandshakeTimeout)
	}
	if transport.ExpectContinueTimeout != src.ExpectContinueTimeout {
		t.Errorf("ExpectContinueTimeout = %v, want %v", transport.ExpectContinueTimeout, src.ExpectContinueTimeout)
	}
}

// TestNewNilTLSConfigKeepsDefaultBehavior verifies backward compatibility: with no
// TLSClientConfig and no Timeout, the Server uses http.DefaultClient exactly as before.
func TestNewNilTLSConfigKeepsDefaultBehavior(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if s.httpClient != nil {
		t.Errorf("expected nil per-Server client for default configuration, got %p", s.httpClient)
	}
	if s.client() != http.DefaultClient {
		t.Error("expected client() to fall back to http.DefaultClient")
	}
}

// TestTimeoutApplied verifies the configurable Timeout is applied to the per-Server client.
func TestTimeoutApplied(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := s.client().Timeout; got != 50*time.Millisecond {
		t.Errorf("client timeout = %v, want %v", got, 50*time.Millisecond)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer ts.Close()

	if _, err := s.client().Get(ts.URL); err == nil {
		t.Error("expected request to exceed the configured timeout, got nil error")
	}
}

// TestConcurrentNewNoRace exercises concurrent construction with a shared TLSClientConfig.
// Under the previous shared-transport mutation this raced; run with -race to confirm it is
// gone. It also asserts the caller's config never leaks onto the global transport.
func TestConcurrentNewNoRace(t *testing.T) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := New(Configuration{ServerURL: "https://example.com", TLSClientConfig: tlsConfig}); err != nil {
				t.Errorf("New returned error: %v", err)
			}
		}()
	}
	wg.Wait()

	if defaultTransportTLSConfig(t) == tlsConfig {
		t.Error("caller's TLSClientConfig leaked onto http.DefaultTransport")
	}
}
