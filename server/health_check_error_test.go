package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The health probes in checkPlatformDetails used to collapse every failure into
// "invalid URL", with the real transport error going only to the logger. These tests
// pin the diagnosis to the returned error so the caller can act on it.
func TestCheckPlatformDetailsSurfacesTLSError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = s.checkPlatformDetails(ts.URL)
	if err == nil {
		t.Fatal("checkPlatformDetails returned no error against an untrusted certificate")
	}

	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Errorf("error does not unwrap to x509.UnknownAuthorityError: %v", err)
	}
	if !strings.Contains(err.Error(), ts.URL) {
		t.Errorf("error does not name the probed URL: %v", err)
	}
	if strings.Contains(err.Error(), "invalid URL") {
		t.Errorf("error still reports the fabricated cause: %v", err)
	}
}

func TestCheckPlatformDetailsSurfacesConnectionError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	s, err := New(Configuration{ServerURL: url})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = s.checkPlatformDetails(url)
	if err == nil {
		t.Fatal("checkPlatformDetails returned no error against a closed listener")
	}
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Errorf("error does not describe the connection failure: %v", err)
	}
	if !strings.Contains(err.Error(), url+"/api/v1/healthcheck") || !strings.Contains(err.Error(), url+"/health") {
		t.Errorf("error does not name both probed URLs: %v", err)
	}
}

func TestCheckPlatformDetailsReachableButUnhealthy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":false}`)
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = s.checkPlatformDetails(ts.URL)
	if err == nil {
		t.Fatal("checkPlatformDetails returned no error for an unhealthy server")
	}
	if !strings.Contains(err.Error(), "responded but neither reported a healthy") {
		t.Errorf("error does not distinguish reachable-but-unhealthy: %v", err)
	}
}

func TestCheckJSONResponseReturnsTransportError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()

	s, err := New(Configuration{ServerURL: url})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	healthy, err := s.checkJSONResponse(url)
	if healthy {
		t.Error("checkJSONResponse reported healthy against a closed listener")
	}
	if err == nil {
		t.Fatal("checkJSONResponse discarded the transport error")
	}
	if !strings.Contains(err.Error(), url) {
		t.Errorf("error does not name the probed URL: %v", err)
	}
}

func TestCheckJSONResponseHealthyBodyWithoutJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Healthy")
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	healthy, err := s.checkJSONResponse(ts.URL)
	if err != nil {
		t.Fatalf("checkJSONResponse returned error: %v", err)
	}
	if !healthy {
		t.Error("checkJSONResponse did not honor the non-JSON healthy body")
	}
}

// healthCheckError has one message per combination of probe outcomes. Each must name
// both probed URLs and keep an underlying error matchable with errors.Is.
func TestHealthCheckErrorVariants(t *testing.T) {
	const ssURL, platformURL = "https://ss.example.com/api/v1/healthcheck", "https://platform.example.com/health"
	ssErr := errors.New("secret server probe failed")
	platformErr := errors.New("platform probe failed")

	// When both probes fail, both causes must be matchable: a caller asking whether it
	// hit an untrusted CA should get an answer regardless of which probe hit it.
	for _, c := range []struct {
		name        string
		ssErr       error
		platformErr error
		wrapped     []error
	}{
		{"both failed", ssErr, platformErr, []error{ssErr, platformErr}},
		{"secret server failed", ssErr, nil, []error{ssErr}},
		{"platform failed", nil, platformErr, []error{platformErr}},
		{"both reachable but unhealthy", nil, nil, nil},
	} {
		err := healthCheckError(ssURL, c.ssErr, platformURL, c.platformErr)
		if err == nil {
			t.Errorf("%s: healthCheckError returned nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), ssURL) || !strings.Contains(err.Error(), platformURL) {
			t.Errorf("%s: error %q does not name both probed URLs", c.name, err)
		}
		for _, want := range c.wrapped {
			if !errors.Is(err, want) {
				t.Errorf("%s: error does not wrap %v: %v", c.name, want, err)
			}
		}
	}
}
