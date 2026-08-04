package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	credentialPassword = "PASSWORD-THAT-MUST-NOT-BE-PRINTED"
	credentialToken    = "TOKEN-THAT-MUST-NOT-BE-PRINTED"
)

func redactionCredential() UserCredential {
	return UserCredential{
		Domain:   "corp.example.com",
		Username: "admin",
		Password: credentialPassword,
		Token:    credentialToken,
	}
}

// A consumer reaches for %v or %+v on whatever it has when a call misbehaves, and what it
// has is a Configuration or a Server. Every verb that walks a struct's fields must reach
// the redaction, including through the embedding in Server.
func TestFormattingRedactsCredentialSecrets(t *testing.T) {
	credential := redactionCredential()
	config := Configuration{ServerURL: "https://redaction.example.com", Credentials: credential}
	s, err := New(config)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	for _, c := range []struct {
		desc   string
		format string
		value  interface{}
	}{
		{"credential with %v", "%v", credential},
		{"credential with %+v", "%+v", credential},
		{"credential with %s", "%s", credential},
		{"credential with %#v", "%#v", credential},
		{"credential pointer with %v", "%v", &credential},
		{"configuration with %v", "%v", config},
		{"configuration with %+v", "%+v", config},
		{"configuration with %#v", "%#v", config},
		{"server with %v", "%v", *s},
		{"server with %+v", "%+v", s},
		{"server with %#v", "%#v", s},
	} {
		out := fmt.Sprintf(c.format, c.value)
		if strings.Contains(out, credentialPassword) {
			t.Errorf("%s printed the password: %s", c.desc, out)
		}
		if strings.Contains(out, credentialToken) {
			t.Errorf("%s printed the token: %s", c.desc, out)
		}
		if !strings.Contains(out, "<redacted>") {
			t.Errorf("%s did not mark the secrets as redacted: %s", c.desc, out)
		}
	}
}

// Redaction is worth nothing if it also hides what the dump is being read for.
func TestFormattingKeepsTheIdentifyingFields(t *testing.T) {
	out := fmt.Sprintf("%+v", Configuration{
		ServerURL:   "https://redaction.example.com",
		Credentials: redactionCredential(),
	})

	for _, want := range []string{"corp.example.com", "admin", "https://redaction.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatted configuration does not name %q: %s", want, out)
		}
	}
}

// An unset secret prints as empty rather than as the redaction, so a dump still answers
// whether a password was configured at all.
func TestFormattingDistinguishesAnUnsetSecret(t *testing.T) {
	out := fmt.Sprintf("%v", UserCredential{Username: "admin"})

	if strings.Contains(out, "<redacted>") {
		t.Errorf("an unset password and token were reported as redacted: %s", out)
	}
	if !strings.Contains(out, "admin") {
		t.Errorf("formatted credential does not name the username: %s", out)
	}
}

func TestJSONRedactsCredentialSecretsButStillDecodesConfiguration(t *testing.T) {
	data, err := json.Marshal(Configuration{
		ServerURL:   "https://redaction.example.com",
		Credentials: redactionCredential(),
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	if strings.Contains(string(data), credentialPassword) || strings.Contains(string(data), credentialToken) {
		t.Errorf("JSON exposed a credential secret: %s", data)
	}
	var redacted Configuration
	if err := json.Unmarshal(data, &redacted); err != nil {
		t.Fatalf("decoding redacted JSON: %v", err)
	}
	if redacted.Credentials.Password != "<redacted>" || redacted.Credentials.Token != "<redacted>" {
		t.Errorf("JSON credential fields were not redacted: %s", data)
	}

	var decoded Configuration
	if err := json.Unmarshal([]byte(`{"Credentials":{"Domain":"corp","Username":"user","Password":"password","Token":"token"},"ServerURL":"https://example.com"}`), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if decoded.Credentials.Password != "password" || decoded.Credentials.Token != "token" {
		t.Errorf("configuration decode lost credential values: %+v", decoded.Credentials)
	}
}
