package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
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

	if after := defaultTransportTLSConfig(t); after == tlsConfig {
		t.Error("the caller's TLSClientConfig leaked onto http.DefaultTransport")
	} else if after != nil && after != before && (after.InsecureSkipVerify || after.RootCAs != nil || after.Certificates != nil) {
		// Transport.Clone may perform synchronized, one-time HTTP/2 initialization on
		// the source transport. That standard-library internal config is acceptable;
		// any caller-controlled verification state is not.
		t.Error("http.DefaultTransport acquired caller-controlled TLS verification state")
	}

	transport, ok := s.client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Server client transport is not an *http.Transport")
	}
	if transport == http.DefaultTransport {
		t.Error("Server transport is the shared http.DefaultTransport; expected a distinct clone")
	}
	if transport.TLSClientConfig == tlsConfig {
		t.Error("Server retained the caller's mutable TLSClientConfig pointer; expected a clone")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Server TLSClientConfig clone did not preserve InsecureSkipVerify")
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

// TestNewFailsClosedWhenTLSCannotBeApplied covers the unchecked type-assertion vector:
// New must not panic or silently bypass a custom transport when it cannot apply TLS.
func TestNewFailsClosedWhenTLSCannotBeApplied(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = stubRoundTripper{}
	defer func() { http.DefaultTransport = original }()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if _, err := New(Configuration{ServerURL: "https://example.com", TLSClientConfig: tlsConfig}); err == nil {
		t.Fatal("New silently accepted TLSClientConfig with a non-cloneable transport")
	} else if !strings.Contains(err.Error(), "*http.Transport") {
		t.Errorf("New error = %q, want it to explain the transport requirement", err)
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

// TestNewDefaultClientIsScopedAndBounded verifies the zero-value network configuration
// receives the SDK's redirect policy and safe default request timeout.
func TestNewDefaultClientIsScopedAndBounded(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if s.httpClient == nil {
		t.Fatal("expected a per-Server client for default configuration")
	}
	if s.client() == http.DefaultClient {
		t.Error("Server uses the process-global client; redirect and timeout policy are not scoped")
	}
	if got := s.client().Timeout; got != defaultHTTPTimeout {
		t.Errorf("default client timeout = %v, want %v", got, defaultHTTPTimeout)
	}
}

func TestDisableTimeoutIsExplicit(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com", DisableTimeout: true})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := s.client().Timeout; got != 0 {
		t.Errorf("client timeout = %v, want no client timeout", got)
	}
}

func TestInjectedClientBehaviorIsPreserved(t *testing.T) {
	transport := stubRoundTripper{}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New returned error: %v", err)
	}
	redirectPolicyCalled := false
	base := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   13 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectPolicyCalled = true
			return nil
		},
	}
	s, err := New(Configuration{ServerURL: "https://example.com", HTTPClient: base})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if s.client() == base {
		t.Error("New reused the caller's client pointer")
	}
	if s.client().Transport != transport || s.client().Jar != jar {
		t.Error("New did not preserve the injected transport and cookie jar")
	}
	if s.client().Timeout != base.Timeout {
		t.Errorf("timeout = %v, want injected %v", s.client().Timeout, base.Timeout)
	}
	redirected := httptest.NewRequest(http.MethodGet, "https://example.com/after", nil)
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://example.com/before", nil)}
	if err := s.client().CheckRedirect(redirected, via); err != nil {
		t.Errorf("same-origin injected redirect policy returned error: %v", err)
	}
	if !redirectPolicyCalled {
		t.Error("New did not preserve the injected redirect policy")
	}
}

func TestTLSClonePreservesAllOperationalTransportSettings(t *testing.T) {
	source := &http.Transport{
		ProxyConnectHeader:     http.Header{"Proxy-Authorization": []string{"Basic opaque"}},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxIdleConns:           17,
		MaxIdleConnsPerHost:    9,
		MaxConnsPerHost:        11,
		ResponseHeaderTimeout:  7 * time.Second,
		ExpectContinueTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 12345,
		ReadBufferSize:         4096,
		WriteBufferSize:        8192,
	}
	s, err := New(Configuration{
		ServerURL:       "https://example.com",
		HTTPClient:      &http.Client{Transport: source},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	cloned, ok := s.client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", s.client().Transport)
	}
	if cloned == source {
		t.Fatal("New reused the caller's mutable transport")
	}
	if cloned.ProxyConnectHeader.Get("Proxy-Authorization") != "Basic opaque" ||
		!cloned.DisableKeepAlives || !cloned.DisableCompression ||
		cloned.MaxIdleConns != source.MaxIdleConns ||
		cloned.MaxIdleConnsPerHost != source.MaxIdleConnsPerHost ||
		cloned.MaxConnsPerHost != source.MaxConnsPerHost ||
		cloned.ResponseHeaderTimeout != source.ResponseHeaderTimeout ||
		cloned.ExpectContinueTimeout != source.ExpectContinueTimeout ||
		cloned.MaxResponseHeaderBytes != source.MaxResponseHeaderBytes ||
		cloned.ReadBufferSize != source.ReadBufferSize ||
		cloned.WriteBufferSize != source.WriteBufferSize {
		t.Errorf("transport clone lost operational settings: got %+v, source %+v", cloned, source)
	}
	if cloned.TLSClientConfig == nil || cloned.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("transport clone did not apply the configured TLS minimum")
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
