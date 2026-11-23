package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newStatusTestClient(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := New(Configuration{
		ServerURL: srv.URL, Credentials: UserCredential{Token: "status-test-token"}, DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func serveSecretJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/secrets/5" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
}

func TestSecretDecodesRotationAndHeartbeatStatus(t *testing.T) {
	client := newStatusTestClient(t, serveSecretJSON(`{"id":5,"name":"db",
		"lastPasswordChangeAttempt":"2026-11-18T09:30:00",
		"lastHeartBeatCheck":"2026-11-19T07:00:00Z",
		"lastHeartBeatStatus":"Success",
		"items":[{"fieldName":"Password","slug":"password","itemValue":"v"}]}`))

	secret, err := client.Secret(5)
	if err != nil {
		t.Fatal(err)
	}
	if secret.LastPasswordChangeAttempt == nil || *secret.LastPasswordChangeAttempt != "2026-11-18T09:30:00" {
		t.Errorf("LastPasswordChangeAttempt = %v", secret.LastPasswordChangeAttempt)
	}
	if secret.LastHeartBeatCheck == nil || *secret.LastHeartBeatCheck != "2026-11-19T07:00:00Z" {
		t.Errorf("LastHeartBeatCheck = %v", secret.LastHeartBeatCheck)
	}
	if secret.LastHeartBeatStatus == nil || *secret.LastHeartBeatStatus != "Success" {
		t.Errorf("LastHeartBeatStatus = %v", secret.LastHeartBeatStatus)
	}

	// Consumers such as External Secrets Operator marshal the struct and
	// read these keys from the resulting JSON.
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"LastPasswordChangeAttempt": "2026-11-18T09:30:00",
		"LastHeartBeatCheck":        "2026-11-19T07:00:00Z",
		"LastHeartBeatStatus":       "Success",
	} {
		if out[key] != want {
			t.Errorf("marshaled %s = %v, want %q", key, out[key], want)
		}
	}
}

func TestSecretStatusNullMissingAndNumeric(t *testing.T) {
	client := newStatusTestClient(t, serveSecretJSON(`{"id":5,"name":"db",
		"lastPasswordChangeAttempt":null,
		"lastHeartBeatStatus":3,
		"items":[]}`))

	secret, err := client.Secret(5)
	if err != nil {
		t.Fatal(err)
	}
	if secret.LastPasswordChangeAttempt != nil || secret.LastHeartBeatCheck != nil {
		t.Errorf("null/missing dates decoded as %v, %v", secret.LastPasswordChangeAttempt, secret.LastHeartBeatCheck)
	}
	if secret.LastHeartBeatStatus == nil || *secret.LastHeartBeatStatus != "3" {
		t.Errorf("numeric LastHeartBeatStatus = %v", secret.LastHeartBeatStatus)
	}

	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"LastPasswordChangeAttempt", "LastHeartBeatCheck"} {
		if strings.Contains(string(encoded), key) {
			t.Errorf("marshaled secret contains %s with no value: %s", key, encoded)
		}
	}
}

func TestHeartbeatStatusRejectsNonScalar(t *testing.T) {
	var status HeartbeatStatus
	if err := json.Unmarshal([]byte(`{"a":1}`), &status); err == nil {
		t.Fatal("expected an error for an object heartbeat status")
	}
}

func TestUpdateSecretOmitsReadOnlyStatus(t *testing.T) {
	var putBody string
	client := newStatusTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/1":
			fmt.Fprint(w, `{"ID":1,"Fields":[{"SecretTemplateFieldID":10,"FieldSlugName":"password"}]}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/5":
			data, _ := io.ReadAll(r.Body)
			putBody = string(data)
			fmt.Fprint(w, `{"ID":5}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5":
			fmt.Fprint(w, `{"ID":5,"LastHeartBeatStatus":"Success","Items":[]}`)
		default:
			http.NotFound(w, r)
		}
	})

	attempt, check, status := "2026-11-18T09:30:00", "2026-11-19T07:00:00Z", HeartbeatStatus("Success")
	if _, err := client.UpdateSecret(Secret{
		ID: 5, SecretTemplateID: 1,
		Fields:                    []SecretField{{Slug: "password", ItemValue: "new"}},
		LastPasswordChangeAttempt: &attempt, LastHeartBeatCheck: &check, LastHeartBeatStatus: &status,
	}); err != nil {
		t.Fatal(err)
	}
	if putBody == "" {
		t.Fatal("no PUT request was sent")
	}
	for _, key := range []string{"LastPasswordChangeAttempt", "LastHeartBeatCheck", "LastHeartBeatStatus"} {
		if strings.Contains(putBody, key) {
			t.Errorf("update request contains read-only %s: %s", key, putBody)
		}
	}
}
