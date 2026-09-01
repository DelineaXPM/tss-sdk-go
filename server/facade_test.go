package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	delinea "github.com/DelineaXPM/delinea-common/api"
)

type closeTrackingTransport struct {
	closeCalls atomic.Int32
}

func (*closeTrackingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func (t *closeTrackingTransport) CloseIdleConnections() {
	t.closeCalls.Add(1)
}

func writeGrant(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"access_token":"facade-test-token","token_type":"Bearer","expires_in":3600}`)
}

func writeSecret(w http.ResponseWriter, id int) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ID":%d,"Name":"test","Items":[{"FieldName":"Password","Slug":"password","ItemValue":"value"}]}`, id)
}

func TestFacadeSecretServerInitializesLazilyAndReusesToken(t *testing.T) {
	var probes, grants, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			probes.Add(1)
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			grants.Add(1)
			writeGrant(w)
		case "/api/v1/secrets/7":
			reads.Add(1)
			writeSecret(w, 7)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Username: "user", Password: "password-value"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if probes.Load()+grants.Load()+reads.Load() != 0 {
		t.Fatal("New performed network I/O")
	}
	for range 2 {
		secret, err := client.Secret(7)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := secret.Field("password"); !ok || got != "value" {
			t.Fatalf("password = %q, %v", got, ok)
		}
	}
	if probes.Load() != 1 || grants.Load() != 1 || reads.Load() != 2 {
		t.Fatalf("probes=%d grants=%d reads=%d, want 1,1,2", probes.Load(), grants.Load(), reads.Load())
	}
}

func TestFacadeCloseIdleConnectionsDelegatesToInitializedClient(t *testing.T) {
	transport := new(closeTrackingTransport)
	client, err := delinea.New(delinea.Config{
		URL:       "https://example.com",
		Token:     "facade-test-token",
		Target:    delinea.TargetSecretServer,
		Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := Server{Configuration: Configuration{runtime: &serverRuntime{client: client}}}
	server.CloseIdleConnections()
	if got := transport.closeCalls.Load(); got != 1 {
		t.Fatalf("CloseIdleConnections delegated %d times, want 1", got)
	}

	// A server remains usable after closing idle connections, and an
	// uninitialized value has nothing to close.
	server.CloseIdleConnections()
	var uninitialized Server
	uninitialized.CloseIdleConnections()
	if got := transport.closeCalls.Load(); got != 2 {
		t.Fatalf("second CloseIdleConnections delegated %d times, want 2", got)
	}
}

func TestFacadePlatformRoutesTypedCallsThroughVault(t *testing.T) {
	var baseURL string
	var ssProbes, platformProbes, grants, brokerCalls, reads atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			ssProbes.Add(1)
			http.NotFound(w, r)
		case "/health":
			platformProbes.Add(1)
			fmt.Fprint(w, `{"healthy":true}`)
		case "/identity/api/oauth2/token/xpmplatform":
			grants.Add(1)
			writeGrant(w)
		case "/vaultbroker/api/vaults":
			brokerCalls.Add(1)
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"v1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, baseURL)
		case "/api/v1/secrets/9":
			reads.Add(1)
			writeSecret(w, 9)
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = srv.URL
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	client, err := New(Configuration{
		ServerURL:       srv.URL,
		Credentials:     UserCredential{Username: "client-id", Password: "client-secret-value"},
		DisableRetries:  true,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Secret(9); err != nil {
			t.Fatal(err)
		}
	}
	if ssProbes.Load() != 1 || platformProbes.Load() != 1 || grants.Load() != 1 || brokerCalls.Load() != 1 || reads.Load() != 2 {
		t.Fatalf("ssProbe=%d platformProbe=%d grants=%d broker=%d reads=%d", ssProbes.Load(), platformProbes.Load(), grants.Load(), brokerCalls.Load(), reads.Load())
	}
}

func TestFacadeRejectsImplicitCloudVaultAlternatePort(t *testing.T) {
	const untrustedVault = "https://x.secretservercloud.com:8443"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			http.NotFound(w, r)
		case "/health":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/identity/api/oauth2/token/xpmplatform":
			writeGrant(w)
		case "/vaultbroker/api/vaults":
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"v1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, untrustedVault)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	client, err := New(Configuration{
		ServerURL: srv.URL,
		Credentials: UserCredential{
			Username: "vault-port-client", Password: "vault-port-secret",
		},
		CACertPEM: string(certPEM), DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(9); err == nil || !strings.Contains(err.Error(), "untrusted vault host") {
		t.Fatalf("got %v, want alternate-port vault rejection", err)
	}
}

func TestFacadeSuppliedTokenSkipsProbeAndGrant(t *testing.T) {
	const token = "supplied-facade-token"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/secrets/3" {
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		writeSecret(w, 3)
	}))
	t.Cleanup(srv.Close)

	client, err := New(Configuration{ServerURL: srv.URL, Credentials: UserCredential{Token: token}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(3); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want one data request", calls.Load())
	}
}

func TestFacadeHTTPErrorUsesRequestBoundRedaction(t *testing.T) {
	const token = "response-reflected-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "rejected "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}))
	t.Cleanup(srv.Close)

	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Token: token},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SecretTemplate(1)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("got %T %v, want *HTTPError", err, err)
	}
	if httpErr.StatusCode != http.StatusForbidden || httpErr.RetryAfter != "7" {
		t.Fatalf("HTTPError = %+v", httpErr)
	}
	if strings.Contains(httpErr.Error(), token) || !strings.Contains(httpErr.Error(), "[REDACTED]") {
		t.Fatalf("unsafe diagnostic: %v", httpErr)
	}
}

func TestFacadeSecretReadErrorWithholdsResponseBody(t *testing.T) {
	const responseSecret = "response-contained-password"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, responseSecret, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "read-error-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Secret(1)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("got %T %v, want *HTTPError", err, err)
	}
	if strings.Contains(httpErr.Error(), responseSecret) || httpErr.Body != withheldDiagnostic {
		t.Fatalf("unsafe secret-read diagnostic: %v", httpErr)
	}
}

func TestFacadeSensitiveWriteErrorWithholdsResponseBody(t *testing.T) {
	const submitted = "submitted-secret-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[{"SecretTemplateFieldID":10,"FieldSlugName":"password","IsPassword":true}]}`)
		case "/api/v1/secrets/":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading request: %v", err)
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "write-error-token"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateSecret(Secret{
		SecretTemplateID: 1,
		Fields:           []SecretField{{Slug: "password", ItemValue: submitted}},
	})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("got %T %v, want *HTTPError", err, err)
	}
	if strings.Contains(httpErr.Error(), submitted) || httpErr.Body != withheldDiagnostic {
		t.Fatalf("unsafe sensitive-request diagnostic: %v", httpErr)
	}
}

func TestFacadeSensitiveQueryErrorWithholdsResponseBody(t *testing.T) {
	const secretPath = `\folder\sensitive-name`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, r.URL.RawQuery)
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "query-error-token"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SecretByPath(secretPath)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("got %T %v, want *HTTPError", err, err)
	}
	if strings.Contains(httpErr.Error(), "sensitive-name") || httpErr.Body != withheldDiagnostic {
		t.Fatalf("unsafe sensitive-query diagnostic: %v", httpErr)
	}
}

func TestFacadeRejectsRemotePlainHTTPByDefault(t *testing.T) {
	config := Configuration{ServerURL: "http://example.com", Credentials: UserCredential{Token: "http-token"}}
	if _, err := New(config); err == nil {
		t.Fatal("remote plaintext HTTP was accepted without explicit opt-in")
	}
	config.AllowInsecureHTTP = true
	if _, err := New(config); err != nil {
		t.Fatalf("explicit plaintext HTTP opt-in was rejected: %v", err)
	}
}

func TestFacadeTLSConfigIsServerScoped(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSecret(w, 4)
	}))
	t.Cleanup(tlsServer.Close)
	pool := x509.NewCertPool()
	pool.AddCert(tlsServer.Certificate())
	defaultTransport := http.DefaultTransport

	client, err := New(Configuration{
		ServerURL:       tlsServer.URL,
		Credentials:     UserCredential{Token: "tls-facade-token"},
		TLSClientConfig: &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(4); err != nil {
		t.Fatal(err)
	}
	if http.DefaultTransport != defaultTransport {
		t.Fatal("New mutated http.DefaultTransport")
	}
}

func TestFacadeTLSConfigMutableFieldsAreSnapshotted(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSecret(w, 4)
	}))
	t.Cleanup(tlsServer.Close)
	callerPool := x509.NewCertPool()
	client, err := New(Configuration{
		ServerURL: tlsServer.URL, Credentials: UserCredential{Token: "tls-snapshot-token"},
		TLSClientConfig: &tls.Config{RootCAs: callerPool}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	callerPool.AddCert(tlsServer.Certificate())
	client.TLSClientConfig.RootCAs.AddCert(tlsServer.Certificate())
	if _, err := client.Secret(4); err == nil {
		t.Fatal("mutating a caller-visible CA pool changed the live client trust boundary")
	}

	trustedPool := x509.NewCertPool()
	trustedPool.AddCert(tlsServer.Certificate())
	trusted, err := New(Configuration{
		ServerURL: tlsServer.URL, Credentials: UserCredential{Token: "tls-snapshot-token"},
		TLSClientConfig: &tls.Config{RootCAs: trustedPool}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Secret(4); err != nil {
		t.Fatalf("snapshotted trusted pool was not applied: %v", err)
	}
}

func TestFacadePEMRootConfigurationValidation(t *testing.T) {
	base := Configuration{ServerURL: "https://example.com", Credentials: UserCredential{Token: "pem-token"}}
	invalid := base
	invalid.CACertPEM = "not a certificate"
	if _, err := New(invalid); err == nil {
		t.Fatal("invalid CACertPEM was accepted")
	}
	conflicting := base
	conflicting.CACertPEM = "not relevant"
	conflicting.TLSClientConfig = &tls.Config{}
	if _, err := New(conflicting); err == nil {
		t.Fatal("CACertPEM and TLSClientConfig were accepted together")
	}
}

func TestFacadeCanceledInitializationDoesNotPoisonWaiter(t *testing.T) {
	firstProbe := make(chan struct{})
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			if probes.Add(1) == 1 {
				close(firstProbe)
				<-r.Context().Done()
				return
			}
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			writeGrant(w)
		case "/api/v1/secrets/5":
			writeSecret(w, 5)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Username: "user", Password: "password-value"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() { _, err := client.SecretContext(leaderCtx, 5); leaderDone <- err }()
	<-firstProbe
	waiterDone := make(chan error, 1)
	go func() { _, err := client.SecretContext(context.Background(), 5); waiterDone <- err }()
	cancel()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("waiter error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter remained poisoned by canceled leader")
	}
	if probes.Load() < 2 {
		t.Fatalf("probes=%d, want a retry", probes.Load())
	}
}

func TestFacadeRequiresNew(t *testing.T) {
	_, err := (Server{Configuration: Configuration{ServerURL: "https://example.com"}}).Secret(1)
	if err == nil || !strings.Contains(err.Error(), "initialized by New") {
		t.Fatalf("got %v, want constructor-required error", err)
	}
}

func TestFacadeConcurrentFirstCallsCoalesceInitialization(t *testing.T) {
	var probes, grants, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			probes.Add(1)
			time.Sleep(10 * time.Millisecond)
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			grants.Add(1)
			writeGrant(w)
		case "/api/v1/secrets/11":
			reads.Add(1)
			writeSecret(w, 11)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Username: "concurrent-user", Password: "concurrent-password"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 20
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Secret(11)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if probes.Load() != 1 || grants.Load() != 1 || reads.Load() != callers {
		t.Fatalf("probes=%d grants=%d reads=%d", probes.Load(), grants.Load(), reads.Load())
	}
}

func TestFacadeConfigurationIsSnapshotted(t *testing.T) {
	const originalToken = "original-snapshot-token"
	var originalCalls, changedCalls atomic.Int32
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originalCalls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+originalToken {
			t.Errorf("Authorization=%q", got)
		}
		writeSecret(w, 12)
	}))
	t.Cleanup(original.Close)
	changed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		changedCalls.Add(1)
		writeSecret(w, 12)
	}))
	t.Cleanup(changed.Close)
	client, err := New(Configuration{ServerURL: original.URL, Credentials: UserCredential{Token: originalToken}})
	if err != nil {
		t.Fatal(err)
	}
	client.ServerURL = changed.URL
	client.Credentials.Token = "changed-snapshot-token"
	if _, err := client.Secret(12); err != nil {
		t.Fatal(err)
	}
	if originalCalls.Load() != 1 || changedCalls.Load() != 0 {
		t.Fatalf("original calls=%d changed calls=%d", originalCalls.Load(), changedCalls.Load())
	}
}

type recordingLogger struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *recordingLogger) append(values ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(&l.buf, values...)
}

func (l *recordingLogger) Printf(format string, values ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", values...)
}

func (l *recordingLogger) Print(values ...interface{})   { l.append(values...) }
func (l *recordingLogger) Println(values ...interface{}) { l.append(values...) }

func (l *recordingLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestFacadeLoggerAdapterKeepsCredentialsRedacted(t *testing.T) {
	const password = "logger-password-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "rejected "+password)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	logger := new(recordingLogger)
	client, err := New(Configuration{
		ServerURL:   srv.URL,
		Credentials: UserCredential{Username: "logger-user", Password: password},
		Logger:      logger, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(1); err == nil {
		t.Fatal("grant unexpectedly succeeded")
	}
	output := logger.String()
	if strings.Contains(output, password) {
		t.Fatalf("logger exposed password: %q", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("logger did not preserve engine redaction marker: %q", output)
	}
}

func TestFacadeLoggerAdapterNeutralizesForgedRecords(t *testing.T) {
	logger := new(recordingLogger)
	slogFor(logger).WithGroup("group\nforged").Info(
		"message\r\nforged\x1b", "key\nforged", "value\rforged\u2066",
	)
	output := logger.String()
	if strings.Count(output, "\n") != 1 || strings.ContainsAny(output, "\r\x1b\u2066") {
		t.Fatalf("logger emitted record-breaking control characters: %q", output)
	}
	if !strings.Contains(output, "message??forged?") {
		t.Fatalf("logger did not visibly neutralize controls: %q", output)
	}
}

func TestCredentialDiagnosticsNeutralizeForgedRecords(t *testing.T) {
	credential := UserCredential{
		Domain: "domain\nforged", Username: "user\r\u2066forged",
		Password: "diagnostic-password", Token: "diagnostic-token",
	}
	for name, diagnostic := range map[string]string{
		"String":   credential.String(),
		"GoString": credential.GoString(),
		"JSON":     string(mustJSON(t, credential)),
	} {
		if strings.ContainsAny(diagnostic, "\n\r\u2066") {
			t.Errorf("%s retained record-breaking characters: %q", name, diagnostic)
		}
		if strings.Contains(diagnostic, credential.Password) || strings.Contains(diagnostic, credential.Token) {
			t.Errorf("%s retained credentials: %q", name, diagnostic)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFacadeAdopts401RefreshAnd403AuthorizationPolicy(t *testing.T) {
	var grants, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			grant := grants.Add(1)
			fmt.Fprintf(w, `{"access_token":"policy-token-%d","token_type":"Bearer","expires_in":3600}`, grant)
		case "/api/v1/secrets/14":
			switch reads.Add(1) {
			case 1:
				writeSecret(w, 14) // prime the memoized token
			case 2:
				w.WriteHeader(http.StatusUnauthorized)
			case 3:
				writeSecret(w, 14) // replay after one fresh grant
			default:
				w.WriteHeader(http.StatusForbidden)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Username: "policy-user", Password: "policy-password"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(14); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(14); err != nil {
		t.Fatalf("401 recovery failed: %v", err)
	}
	if _, err := client.Secret(14); err == nil {
		t.Fatal("403 unexpectedly succeeded")
	}
	if grants.Load() != 2 || reads.Load() != 4 {
		t.Fatalf("grants=%d reads=%d, want 2 and 4", grants.Load(), reads.Load())
	}
}

func TestFacadeRecoversFromSecretServerExpiredToken403(t *testing.T) {
	var grants, reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/healthcheck":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/oauth2/token":
			grant := grants.Add(1)
			fmt.Fprintf(w, `{"access_token":"expired-policy-token-%d","token_type":"Bearer","expires_in":3600}`, grant)
		case "/api/v1/secrets/15":
			switch reads.Add(1) {
			case 1:
				writeSecret(w, 15) // prime and retain the first token
			case 2:
				if got := r.Header.Get("Authorization"); got != "Bearer expired-policy-token-1" {
					t.Errorf("stale request authorization = %q, want first token", got)
				}
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"message":"Authentication failed or expired token."}`)
			case 3:
				if got := r.Header.Get("Authorization"); got != "Bearer expired-policy-token-2" {
					t.Errorf("replayed request authorization = %q, want refreshed token", got)
				}
				writeSecret(w, 15)
			default:
				t.Errorf("unexpected secret read %d", reads.Load())
				http.Error(w, "unexpected request", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := New(Configuration{
		ServerURL:      srv.URL,
		Credentials:    UserCredential{Username: "expired-policy-user", Password: "expired-policy-password"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Secret(15); err != nil {
		t.Fatal(err)
	}
	secret, err := client.Secret(15)
	if err != nil {
		t.Fatalf("expired-token recovery failed: %v", err)
	}
	if secret.ID != 15 {
		t.Errorf("secret ID = %d, want 15", secret.ID)
	}
	if grants.Load() != 2 || reads.Load() != 3 {
		t.Fatalf("grants=%d reads=%d, want 2 and 3", grants.Load(), reads.Load())
	}
}

func TestFacadeRetryAndResponseLimitMapping(t *testing.T) {
	t.Run("MaxRetries counts retries", func(t *testing.T) {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if attempts.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeSecret(w, 6)
		}))
		t.Cleanup(srv.Close)
		client, err := New(Configuration{
			ServerURL: srv.URL, Credentials: UserCredential{Token: "retry-facade-token"},
			MaxRetries: 2, RetryBaseDelay: time.Nanosecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Secret(6); err != nil {
			t.Fatal(err)
		}
		if attempts.Load() != 3 {
			t.Fatalf("attempts=%d, want 3", attempts.Load())
		}
	})

	t.Run("DisableRetries selects one attempt", func(t *testing.T) {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)
		client, err := New(Configuration{
			ServerURL: srv.URL, Credentials: UserCredential{Token: "no-retry-facade-token"},
			DisableRetries: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Secret(6); err == nil {
			t.Fatal("request unexpectedly succeeded")
		}
		if attempts.Load() != 1 {
			t.Fatalf("attempts=%d, want 1", attempts.Load())
		}
	})

	t.Run("MaxResponseBytes caps success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "12345")
		}))
		t.Cleanup(srv.Close)
		client, err := New(Configuration{
			ServerURL: srv.URL, Credentials: UserCredential{Token: "limit-facade-token"},
			MaxResponseBytes: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Secret(6); err == nil || !strings.Contains(err.Error(), "exceeded 4 bytes") {
			t.Fatalf("got %v, want response-cap error", err)
		}
	})
}

func TestFacadeLegacyOperationTimeoutIsTotal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flushing")
			return
		}
		fmt.Fprint(w, `{"ID":1`)
		flusher.Flush()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				fmt.Fprint(w, " ")
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "total-timeout-token"},
		Timeout: 50 * time.Millisecond, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Secret(1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("legacy operation exceeded its total deadline: %v", elapsed)
	}
}

func TestFacadeAttachmentBudgetsCoverWholeOperation(t *testing.T) {
	t.Run("response bytes are cumulative", func(t *testing.T) {
		const metadata = `{"ID":1,"Items":[{"Slug":"file","IsFile":true,"FileAttachmentID":1,"Filename":"file.txt"}]}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/secrets/1":
				fmt.Fprint(w, metadata)
			case "/api/v1/secrets/1/fields/file":
				fmt.Fprint(w, "1234567890")
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		client, err := New(Configuration{
			ServerURL: srv.URL, Credentials: UserCredential{Token: "cumulative-limit-token"},
			MaxResponseBytes: int64(len(metadata) + 5), DisableRetries: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Secret(1); err == nil || !strings.Contains(err.Error(), "exceeded 5 bytes") {
			t.Fatalf("got %v, want cumulative response-cap error", err)
		}
	})

	t.Run("attachment downloads are counted", func(t *testing.T) {
		const metadata = `{"ID":2,"Items":[{"Slug":"one","IsFile":true,"FileAttachmentID":1,"Filename":"one.txt"},{"Slug":"two","IsFile":true,"FileAttachmentID":2,"Filename":"two.txt"}]}`
		var downloads atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/secrets/2" {
				fmt.Fprint(w, metadata)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/2/fields/") {
				downloads.Add(1)
				fmt.Fprint(w, "file")
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)
		client, err := New(Configuration{
			ServerURL: srv.URL, Credentials: UserCredential{Token: "attachment-count-token"},
			MaxAttachmentDownloads: 1, DisableRetries: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Secret(2); err == nil || !strings.Contains(err.Error(), "exceeded 1 attachment downloads") {
			t.Fatalf("got %v, want attachment-count error", err)
		}
		if downloads.Load() != 1 {
			t.Fatalf("downloads=%d, want one", downloads.Load())
		}
	})
}

func TestFacadeCrossServerCacheDependsOnTLSOpacity(t *testing.T) {
	t.Run("ordinary servers share a grant", func(t *testing.T) {
		var grants atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/healthcheck":
				fmt.Fprint(w, `{"healthy":true}`)
			case "/oauth2/token":
				grants.Add(1)
				writeGrant(w)
			case "/api/v1/secrets/8":
				writeSecret(w, 8)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		config := Configuration{
			ServerURL:      srv.URL,
			Credentials:    UserCredential{Username: "cache-user", Password: "cache-password-value"},
			DisableRetries: true,
		}
		first, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		second, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.Secret(8); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Secret(8); err != nil {
			t.Fatal(err)
		}
		if grants.Load() != 1 {
			t.Fatalf("grants=%d, want one shared grant", grants.Load())
		}
	})

	t.Run("TLS-configured servers retain only local reuse", func(t *testing.T) {
		var grants atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/healthcheck":
				fmt.Fprint(w, `{"healthy":true}`)
			case "/oauth2/token":
				grants.Add(1)
				writeGrant(w)
			case "/api/v1/secrets/8":
				writeSecret(w, 8)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		config := Configuration{
			ServerURL:       srv.URL,
			Credentials:     UserCredential{Username: "tls-cache-user", Password: "tls-cache-password-value"},
			TLSClientConfig: &tls.Config{RootCAs: pool}, DisableRetries: true,
		}
		first, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		second, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.Secret(8); err != nil {
			t.Fatal(err)
		}
		if _, err := first.Secret(8); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Secret(8); err != nil {
			t.Fatal(err)
		}
		if grants.Load() != 2 {
			t.Fatalf("grants=%d, want one per TLS-configured Server", grants.Load())
		}
	})

	t.Run("PEM-configured servers share a grant", func(t *testing.T) {
		var grants atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/healthcheck":
				fmt.Fprint(w, `{"healthy":true}`)
			case "/oauth2/token":
				grants.Add(1)
				writeGrant(w)
			case "/api/v1/secrets/8":
				writeSecret(w, 8)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		config := Configuration{
			ServerURL: srv.URL,
			Credentials: UserCredential{
				Username: "pem-cache-user", Password: "pem-cache-password-value",
			},
			CACertPEM: string(certPEM), DisableRetries: true,
		}
		first, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		second, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.Secret(8); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Secret(8); err != nil {
			t.Fatal(err)
		}
		if grants.Load() != 1 {
			t.Fatalf("grants=%d, want one shared grant", grants.Load())
		}
	})
}

func TestFacadeRequestBodiesAreBounded(t *testing.T) {
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[{"SecretTemplateFieldID":10,"FieldSlugName":"notes"}]}`)
		case "/api/v1/secrets/":
			writes.Add(1)
			fmt.Fprint(w, `{"ID":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "request-limit-token"},
		MaxRequestBytes: 2048, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateSecret(Secret{
		SecretTemplateID: 1,
		Fields:           []SecretField{{Slug: "notes", ItemValue: strings.Repeat("x", 4096)}},
	})
	if err == nil || !strings.Contains(err.Error(), "request body exceeded 2048 bytes") {
		t.Fatalf("got %v, want request-size error", err)
	}
	if writes.Load() != 0 {
		t.Fatalf("oversized request reached the server %d times", writes.Load())
	}
}

func TestRequestSizePreflightsMatchEncodedBodies(t *testing.T) {
	secret := Secret{
		Name: "<name>\n\ufffd",
		Fields: []SecretField{{
			FieldName: "field", Slug: "slug", FieldDescription: "description",
			Filename: "file.txt", ItemValue: string([]byte{'a', 0xff, '\t'}),
		}},
	}
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	size, err := secretJSONSize(secret, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(encoded)) {
		t.Fatalf("JSON preflight=%d encoded=%d", size, len(encoded))
	}

	filename := "safe\r\nquoted\"\\.txt"
	wantSize, err := multipartBodySize(filename, 7)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, "1234567")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if wantSize != int64(body.Len()) {
		t.Fatalf("multipart preflight=%d encoded=%d", wantSize, body.Len())
	}

	extensionless := "private-key"
	wantSize, err = multipartBodySizeParts(extensionless, ".txt", 7)
	if err != nil {
		t.Fatal(err)
	}
	body.Reset()
	writer = multipart.NewWriter(&body)
	part, err = writer.CreateFormFile("file", extensionless+".txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, "1234567")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if wantSize != int64(body.Len()) {
		t.Fatalf("multipart suffix preflight=%d encoded=%d", wantSize, body.Len())
	}

	patch := newFileDeletionPatch("unsafe\nslug\ufffd")
	encodedPatch, err := json.Marshal(patch)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileDeletionPatchJSONSize("unsafe\nslug\ufffd"); got != int64(len(encodedPatch)) {
		t.Fatalf("file patch preflight=%d encoded=%d", got, len(encodedPatch))
	}
}

func TestFacadeCreateReturnsPartialResultAfterAttachmentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[{"SecretTemplateFieldID":10,"FieldSlugName":"file","IsFile":true}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			fmt.Fprint(w, `{"ID":77}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/77/fields/file":
			http.Error(w, "upload rejected", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "partial-write-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateSecret(Secret{
		SecretTemplateID: 1,
		Fields:           []SecretField{{Slug: "file", Filename: "a.txt", ItemValue: "contents"}},
	})
	var partial *PartialWriteError
	if result == nil || result.ID != 77 || !errors.As(err, &partial) || partial.SecretID != 77 {
		t.Fatalf("result=%+v error=%T %v partial=%+v", result, err, err, partial)
	}
}

func TestFacadeSearchPaginatesAndHonorsResultLimit(t *testing.T) {
	var searchCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets" {
			searchCalls.Add(1)
			skip, _ := strconv.Atoi(r.URL.Query().Get("paging.skip"))
			count := 0
			switch skip {
			case 0:
				count = searchPageSize
			case searchPageSize:
				count = 1
			}
			records := make([]Secret, count)
			for i := range records {
				records[i].ID = skip + i + 1
			}
			_ = json.NewEncoder(w).Encode(SearchResult{Records: records})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") {
			id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/"))
			writeSecret(w, id)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "pagination-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := client.Secrets("test", "Name")
	if err != nil || len(secrets) != searchPageSize+1 || searchCalls.Load() != 2 {
		t.Fatalf("len=%d calls=%d error=%v", len(secrets), searchCalls.Load(), err)
	}

	limited, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "pagination-token"},
		MaxSearchResults: searchPageSize, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Secrets("test", "Name"); err == nil || !strings.Contains(err.Error(), "search exceeded 30 results") {
		t.Fatalf("got %v, want search limit error", err)
	}
}

func TestLocalErrorsNeutralizeRecordSeparators(t *testing.T) {
	_, updateErr := (Server{}).UpdateSecretContext(context.Background(), Secret{
		ID: 1, Name: "safe\nFORGED\u2028FORGED", SshKeyArgs: &SshKeyArgs{GenerateSshKeys: true},
	})
	template := &SecretTemplate{Name: "template\rFORGED\u2029FORGED"}
	_, templateErr := (Server{}).GeneratePasswordContext(context.Background(), "slug\nFORGED\u2028FORGED", template)
	for name, err := range map[string]error{"update": updateErr, "template": templateErr} {
		if err == nil || strings.ContainsAny(err.Error(), "\r\n\u2028\u2029") {
			t.Errorf("%s error retained a record separator: %q", name, err)
		}
	}
}

func TestGeneratePasswordRejectsNonpositiveFieldIDWithoutRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "generate-password-id-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{0, -1} {
		template := &SecretTemplate{
			Name: "invalid", Fields: []SecretTemplateField{{SecretTemplateFieldID: id, FieldSlugName: "password"}},
		}
		if _, err := client.GeneratePassword("password", template); err == nil ||
			!strings.Contains(err.Error(), "nonpositive ID") {
			t.Errorf("field ID %d: got %v, want nonpositive-ID error", id, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid field IDs reached the server %d times", requests.Load())
	}
}

func TestFacadeRejectsInvalidWriteResponseIDsBeforeFollowups(t *testing.T) {
	var followups atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/77":
			fmt.Fprint(w, `{"ID":88,"Name":"wrong object"}`)
		default:
			followups.Add(1)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "write-id-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	created, err := client.CreateSecret(Secret{SecretTemplateID: 1})
	var partial *PartialWriteError
	if created == nil || created.ID != 0 || !errors.As(err, &partial) ||
		partial.SecretID != 0 || partial.Stage != "validating the write response" {
		t.Fatalf("create result=%+v error=%T %v partial=%+v", created, err, err, partial)
	}

	updated, err := client.UpdateSecret(Secret{ID: 77, SecretTemplateID: 1})
	partial = nil
	if updated == nil || updated.ID != 77 || !errors.As(err, &partial) ||
		partial.SecretID != 77 || partial.Stage != "validating the write response" {
		t.Fatalf("update result=%+v error=%T %v partial=%+v", updated, err, err, partial)
	}
	if updated.Name != "" {
		t.Fatalf("mismatched update response leaked untrusted fields into the partial result: %+v", updated)
	}
	if followups.Load() != 0 {
		t.Fatalf("invalid response IDs triggered %d follow-up requests", followups.Load())
	}
}

func TestFacadeMalformedCreateResponseDoesNotExposePartialIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			// ID and Name are populated by json.Unmarshal before it reaches the
			// malformed tail. Neither value is trustworthy after decoding fails.
			fmt.Fprint(w, `{"ID":77,"Name":"untrusted"`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "malformed-create-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	created, err := client.CreateSecret(Secret{SecretTemplateID: 1})
	var partial *PartialWriteError
	if created == nil || created.ID != 0 || created.Name != "" || !errors.As(err, &partial) ||
		partial.SecretID != 0 || partial.Stage != "decoding the write response" {
		t.Fatalf("create result=%+v error=%T %v partial=%+v", created, err, err, partial)
	}
}

func TestFacadeFileFieldIDCarriesResolvedSlugIntoUpload(t *testing.T) {
	var uploads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[{"SecretTemplateFieldID":10,"FieldSlugName":"file","IsFile":true}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			fmt.Fprint(w, `{"ID":77}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/77/fields/file":
			uploads.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/77":
			fmt.Fprint(w, `{"ID":77}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "field-id-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	created, err := client.CreateSecret(Secret{
		SecretTemplateID: 1,
		Fields:           []SecretField{{FieldID: 10, Filename: "a.txt", ItemValue: "contents"}},
	})
	if err != nil || created == nil || created.ID != 77 || uploads.Load() != 1 {
		t.Fatalf("create result=%+v uploads=%d error=%v", created, uploads.Load(), err)
	}
}

func TestFacadeDoesNotFollowMutationRedirect(t *testing.T) {
	var initial, redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			initial.Add(1)
			http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
		case r.URL.Path == "/redirected":
			redirected.Add(1)
			fmt.Fprint(w, `{"ID":77}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "mutation-redirect-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateSecret(Secret{SecretTemplateID: 1}); err == nil {
		t.Fatal("mutation redirect was accepted")
	}
	if initial.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("requests: initial=%d redirected=%d, want 1 and 0", initial.Load(), redirected.Load())
	}
}

func TestFacadeRejectsNonpositiveDeleteIDsWithoutRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "delete-id-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []int{0, -1} {
		if err := client.DeleteSecret(id); err == nil || !strings.Contains(err.Error(), "secret ID must be positive") {
			t.Errorf("DeleteSecret(%d): got %v", id, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("nonpositive deletes made %d requests", requests.Load())
	}
}

func TestFacadeValidatesReadResponseIDsBeforeFollowups(t *testing.T) {
	var attachmentRequests, writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/7":
			fmt.Fprint(w, `{"ID":8,"Items":[{"Slug":"file","IsFile":true,"FileAttachmentID":1,"Filename":"file.txt"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/0":
			fmt.Fprint(w, `{"ID":0,"Items":[{"Slug":"file","IsFile":true,"FileAttachmentID":1,"Filename":"file.txt"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/4":
			fmt.Fprint(w, `{"ID":5,"Fields":[]}`)
		case strings.Contains(r.URL.Path, "/fields/"):
			attachmentRequests.Add(1)
			fmt.Fprint(w, "unexpected attachment")
		case r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch:
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "response-id-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Secret(0); err == nil || !strings.Contains(err.Error(), "secret ID must be positive") {
		t.Fatalf("zero requested secret ID: %v", err)
	}
	if _, err := client.SecretTemplate(0); err == nil || !strings.Contains(err.Error(), "secret template ID must be positive") {
		t.Fatalf("zero requested template ID: %v", err)
	}
	if _, err := client.Secret(7); err == nil || !strings.Contains(err.Error(), "response ID 8 does not match the requested ID 7") {
		t.Fatalf("mismatched secret response: %v", err)
	}
	if _, err := client.SecretByPath("/folder/secret"); err == nil || !strings.Contains(err.Error(), "no positive secret ID") {
		t.Fatalf("zero secret-by-path response ID: %v", err)
	}
	if _, err := client.SecretTemplate(4); err == nil || !strings.Contains(err.Error(), "response ID 5 does not match the requested ID 4") {
		t.Fatalf("mismatched template response: %v", err)
	}
	if _, err := client.CreateSecret(Secret{SecretTemplateID: 4}); err == nil || !strings.Contains(err.Error(), "response ID 5 does not match the requested ID 4") {
		t.Fatalf("create with mismatched template response: %v", err)
	}
	if attachmentRequests.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("untrusted response identities triggered attachment requests=%d writes=%d", attachmentRequests.Load(), writes.Load())
	}
}

func TestRequestTargetPreflightsMatchStandardEscaping(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	values := []string{"", "plain text", "slashes/and?query=value", string(allBytes), "世界"}
	for _, value := range values {
		if got, want := queryEscapedLength(value), int64(len(url.QueryEscape(value))); got != want {
			t.Errorf("query length for %q = %d, want %d", value, got, want)
		}
		if got, want := pathEscapedLength(value), int64(len(url.PathEscape(value))); got != want {
			t.Errorf("path length for %q = %d, want %d", value, got, want)
		}
	}
	query := url.Values{"z": {"one", "two words"}, "a": {"/"}}
	if got, want := requestTargetLength("/base", query), int64(len("/base?"+query.Encode())); got != want {
		t.Fatalf("request target length = %d, want %d", got, want)
	}

	server := Server{Configuration: Configuration{apiPathURI: "api/v1"}}
	prefix, segment := "1/fields/", strings.Repeat("/", 100)
	server.MaxRequestBytes = joinedLength(int64(len(server.requestPath(resource, prefix))), pathEscapedLength(segment)) - 1
	if _, err := server.pathWithEscapedSegment(resource, prefix, segment); err == nil {
		t.Fatal("oversized escaped path was accepted")
	}
}

func TestDiagnosticsRemainSingleLineValidUTF8(t *testing.T) {
	value := strings.Repeat("a", errorBodyLength-1) + "é\u2028FORGED\u2029"
	got := truncateDiagnostic(value, errorBodyLength)
	if !utf8.ValidString(got) {
		t.Fatalf("diagnostic is invalid UTF-8: %q", got)
	}
	if strings.ContainsAny(got, "\r\n\u2028\u2029") {
		t.Fatalf("diagnostic retained a record separator: %q", got)
	}
	if got := truncateDiagnostic(strings.Repeat("x", errorBodyLength), errorBodyLength); strings.HasSuffix(got, "...") {
		t.Fatalf("exact-length diagnostic was marked truncated: %q", got)
	}
}
