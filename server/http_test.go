package server

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

// TestHandleResponseClosesBody verifies handleResponse closes the response body on
// both the success and error paths. Every API call funnels through handleResponse,
// so an unclosed body leaks the underlying connection on every request.
func TestHandleResponseClosesBody(t *testing.T) {
	for _, res := range []*http.Response{
		{StatusCode: http.StatusOK, Status: "200 OK"},
		{StatusCode: http.StatusNotFound, Status: "404 Not Found"},
	} {
		body := &closeTrackingBody{Reader: strings.NewReader("payload")}
		res.Body = body
		Server{}.handleResponse(res, nil)
		if !body.closed {
			t.Errorf("%s: response body was not closed", res.Status)
		}
	}
}

// A non-2xx response surfaces its body in the returned error, so a long body is
// truncated to keep the error readable and bounded.
func TestHandleResponseTruncatesLongErrorBody(t *testing.T) {
	res := &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Body:       ioutil.NopCloser(strings.NewReader(strings.Repeat("a", 4000))),
	}

	_, _, err := Server{}.handleResponse(res, nil)
	if err == nil {
		t.Fatal("expected an error for a 400 response, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, strings.Repeat("a", errorBodyLength+1)) {
		t.Errorf("error body was not truncated to %d bytes: %d-char message", errorBodyLength, len(msg))
	}
	if !strings.HasSuffix(msg, "...") {
		t.Errorf("truncated error should end with an ellipsis, got %q", msg)
	}
}

// A short error body is passed through intact, since it is the server's explanation of
// the failure.
func TestHandleResponseKeepsShortErrorBody(t *testing.T) {
	res := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       ioutil.NopCloser(strings.NewReader(`{"errorCode":"API_AccessDenied"}`)),
	}

	_, _, err := Server{}.handleResponse(res, nil)
	if err == nil {
		t.Fatal("expected an error for a 403 response, got nil")
	}
	if !strings.Contains(err.Error(), "API_AccessDenied") {
		t.Errorf("error = %q, want it to carry the server's explanation", err)
	}
	if !strings.Contains(err.Error(), "403 Forbidden") {
		t.Errorf("error = %q, want it to carry the HTTP status", err)
	}
}

// DiscardLogger is the default: every method must be a safe no-op, since the SDK logs
// on paths that handle secret material.
func TestDiscardLoggerMethodsAreSafeNoOps(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com", Logger: &DiscardLogger{}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	logger := s.log()
	if _, ok := logger.(*DiscardLogger); !ok {
		t.Fatalf("log() returned %T, want *DiscardLogger", logger)
	}
	logger.Printf("format %s", "value")
	logger.Print("print")
	logger.Println("println")
}
