package server

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSafeReadRetriesRetryableStatuses(t *testing.T) {
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "temporary")
			return
		}
		fmt.Fprint(w, `{"id":1,"fields":[]}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:      ts.URL,
		Credentials:    UserCredential{Token: "supplied"},
		RetryBaseDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	secret, err := s.Secret(1)
	if err != nil {
		t.Fatalf("Secret returned error after transient failures: %v", err)
	}
	if secret.ID != 1 || requests != 3 {
		t.Errorf("Secret ID / requests = %d / %d, want 1 / 3", secret.ID, requests)
	}
}

func TestUnsafeMethodsAreNeverRetried(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			requests := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer ts.Close()
			s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Token: "supplied"}, RetryBaseDelay: time.Millisecond})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}
			if _, err := s.accessResource(method, resource, "1", struct{}{}); err == nil {
				t.Fatal("retryable status returned no error")
			}
			if requests != 1 {
				t.Errorf("requests = %d, want exactly one for %s", requests, method)
			}
		})
	}
}

type temporaryNetworkError struct{}

func (temporaryNetworkError) Error() string   { return "temporary network failure" }
func (temporaryNetworkError) Timeout() bool   { return false }
func (temporaryNetworkError) Temporary() bool { return true }

type retryTransport struct {
	mu       sync.Mutex
	requests int
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests++
	if t.requests == 1 {
		return nil, temporaryNetworkError{}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(strings.NewReader(`{"id":2,"fields":[]}`)),
		Request:    req,
	}, nil
}

func TestSafeReadRetriesTemporaryTransportError(t *testing.T) {
	transport := &retryTransport{}
	s, err := New(Configuration{
		ServerURL:      "https://example.test",
		Credentials:    UserCredential{Token: "supplied"},
		HTTPClient:     &http.Client{Transport: transport},
		RetryBaseDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	secret, err := s.Secret(2)
	if err != nil {
		t.Fatalf("Secret returned error: %v", err)
	}
	if secret.ID != 2 || transport.requests != 2 {
		t.Errorf("Secret ID / requests = %d / %d, want 2 / 2", secret.ID, transport.requests)
	}
}

func TestContextCancelsRequestAndRetryBackoff(t *testing.T) {
	t.Run("in-flight request", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer ts.Close()
		s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Token: "supplied"}})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := s.SecretContext(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("SecretContext error = %v, want context deadline", err)
		}
	})

	t.Run("retry backoff", func(t *testing.T) {
		requests := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer ts.Close()
		s, err := New(Configuration{ServerURL: ts.URL, Credentials: UserCredential{Token: "supplied"}, RetryBaseDelay: time.Second})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := s.SecretContext(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("SecretContext error = %v, want context deadline", err)
		}
		if requests != 1 {
			t.Errorf("requests = %d, want cancellation before retry", requests)
		}
	})
}

// TestRetryDelaySaturatesAtCap pins the backoff growth to the documented policy:
// the base doubles per attempt until it reaches maximumRetryDelay, so with jitter
// of 50%-150% every delay for a saturated attempt lies in [cap/2, cap]. The
// previous guard stopped doubling at half the cap, so a base in (cap/2, cap] never
// grew at all and later attempts could produce delays below cap/2.
func TestRetryDelaySaturatesAtCap(t *testing.T) {
	for _, base := range []time.Duration{3 * time.Second, 100 * time.Millisecond} {
		s, err := New(Configuration{ServerURL: "https://example.invalid", Credentials: UserCredential{Token: "supplied"}, RetryBaseDelay: base})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}
		for i := 0; i < 64; i++ {
			delay := s.retryDelay(10, nil)
			if delay < maximumRetryDelay/2 || delay > maximumRetryDelay {
				t.Fatalf("retryDelay(10) with base %v = %v, want within [%v, %v]", base, delay, maximumRetryDelay/2, maximumRetryDelay)
			}
		}
	}
}
