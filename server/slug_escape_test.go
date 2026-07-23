package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUploadFileEscapesSlug covers the #9 hardening: a server-provided Slug is
// url.PathEscape'd before being interpolated into the request path, so a Slug with
// path-significant characters cannot alter the URL structure. The same escaping is
// applied at the other Slug-in-path sites in secret.go.
func TestUploadFileEscapesSlug(t *testing.T) {
	var gotRawPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = s.uploadFile(1, SecretField{Slug: "a/b c", Filename: "f.txt", ItemValue: "data"})
	if err != nil {
		t.Fatalf("uploadFile returned error: %v", err)
	}

	if !strings.HasSuffix(gotRawPath, "/fields/a%2Fb%20c") {
		t.Errorf("request path = %q, want it to end with the escaped slug %q", gotRawPath, "/fields/a%2Fb%20c")
	}
}
