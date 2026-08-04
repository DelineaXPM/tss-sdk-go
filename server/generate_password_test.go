package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func generatePasswordTestServer(t *testing.T, body string) (*Server, *int) {
	t.Helper()
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)

	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return s, &requests
}

var generatePasswordTemplate = &SecretTemplate{
	Name: "template",
	ID:   1,
	Fields: []SecretTemplateField{
		{SecretTemplateFieldID: 5, FieldSlugName: "password", IsPassword: true},
	},
}

// TestGeneratePasswordParsesJSONString verifies the response is decoded as the JSON
// string the endpoint returns, including escape handling.
func TestGeneratePasswordParsesJSONString(t *testing.T) {
	s, _ := generatePasswordTestServer(t, `"p4ss\"word"`)

	got, err := s.GeneratePassword("password", generatePasswordTemplate)
	if err != nil {
		t.Fatalf("GeneratePassword returned error: %v", err)
	}
	if want := `p4ss"word`; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
}

// TestGeneratePasswordEmptyResponseNoPanic guards the former blind slice of the
// first and last response byte, which panicked on a body shorter than two bytes.
func TestGeneratePasswordEmptyResponseNoPanic(t *testing.T) {
	s, _ := generatePasswordTestServer(t, "")

	if _, err := s.GeneratePassword("password", generatePasswordTemplate); err == nil {
		t.Error("expected an error for an empty generate-password response, got nil")
	}
}

// TestGeneratePasswordRejectsNonPasswordResponses verifies a JSON null and a JSON
// empty string are errors: null unmarshals into a plain string as a no-op, so both
// would otherwise be returned to the caller as a valid empty password.
func TestGeneratePasswordRejectsNonPasswordResponses(t *testing.T) {
	for _, body := range []string{`null`, `""`} {
		s, _ := generatePasswordTestServer(t, body)

		if _, err := s.GeneratePassword("password", generatePasswordTemplate); err == nil {
			t.Errorf("expected an error for generate-password response %s, got nil", body)
		}
	}
}

// TestGeneratePasswordRejectsUnknownSlug verifies an unknown slug is an error and no
// request is sent, instead of the former behavior of proceeding with field ID 0.
func TestGeneratePasswordRejectsUnknownSlug(t *testing.T) {
	s, requests := generatePasswordTestServer(t, `"unused"`)

	if _, err := s.GeneratePassword("no-such-field", generatePasswordTemplate); err == nil {
		t.Error("expected an error for an unknown slug, got nil")
	}
	if *requests != 0 {
		t.Errorf("expected no HTTP request for an unknown slug, got %d", *requests)
	}
}
