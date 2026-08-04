package server

import (
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestHandleResponseRejectsOversizedBody verifies an API response larger than
// maxResponseBytes is rejected with an error rather than read into memory without
// bound (or silently truncated).
func TestHandleResponseRejectsOversizedBody(t *testing.T) {
	res := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       ioutil.NopCloser(io.LimitReader(zeroReader{}, defaultMaxResponseBytes+10)),
	}

	data, _, err := Server{}.handleResponse(res, nil)
	if err == nil {
		t.Fatal("expected an error for an oversized response body, got nil")
	}
	if data != nil {
		t.Errorf("expected nil data for an oversized response body, got %d bytes", len(data))
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want it to report the exceeded size limit", err)
	}
}

// TestMaxResponseBytesConfigurable verifies Configuration.MaxResponseBytes overrides
// the default response-body cap in both directions: a body over the configured limit
// is rejected and one at the limit is accepted.
func TestMaxResponseBytesConfigurable(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com", MaxResponseBytes: 64})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	over := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       ioutil.NopCloser(strings.NewReader(strings.Repeat("x", 65))),
	}
	if _, _, err := s.handleResponse(over, nil); err == nil {
		t.Error("expected an error for a body over the configured MaxResponseBytes, got nil")
	}

	within := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       ioutil.NopCloser(strings.NewReader(strings.Repeat("x", 64))),
	}
	data, _, err := s.handleResponse(within, nil)
	if err != nil {
		t.Errorf("expected a body at the configured MaxResponseBytes to succeed, got %v", err)
	}
	if len(data) != 64 {
		t.Errorf("data length = %d, want 64", len(data))
	}
}

// A cap of math.MaxInt64 must still read the body: handleResponse reads limit+1 bytes
// to detect an oversized body, and without the clamp that addition overflows to a
// negative LimitReader bound, silently returning every response as empty.
func TestMaxResponseBytesAtMaxInt64ReadsTheBody(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com", MaxResponseBytes: math.MaxInt64})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	res := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       ioutil.NopCloser(strings.NewReader("payload")),
	}
	data, _, err := s.handleResponse(res, nil)
	if err != nil {
		t.Fatalf("handleResponse returned error: %v", err)
	}
	if string(data) != "payload" {
		t.Errorf("data = %q, want %q", data, "payload")
	}
}

// TestCheckJSONResponseRejectsOversizedBody verifies a health probe larger than
// maxHealthResponseBytes is treated as unhealthy with an error, even if the body
// contains the "Healthy" marker.
func TestCheckJSONResponseRejectsOversizedBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Healthy"))
		w.Write(make([]byte, maxHealthResponseBytes))
	}))
	defer ts.Close()

	s, err := New(Configuration{ServerURL: ts.URL})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	healthy, err := s.checkJSONResponse(ts.URL)
	if healthy {
		t.Error("an oversized health response was reported healthy")
	}
	if err == nil {
		t.Error("expected an error for an oversized health response, got nil")
	}
}
