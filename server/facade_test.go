package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	_, err = client.Secret(1)
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
}
