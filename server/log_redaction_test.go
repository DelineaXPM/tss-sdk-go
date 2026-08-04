package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// capturingLogger records what the logger was actually asked to write, arguments
// included. mockLogger keeps only the format string and drops Print's arguments
// entirely, so a response body passed as an argument would leave no trace in it and a
// redaction test written against it could not fail no matter what the SDK logged.
type capturingLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *capturingLogger) Printf(format string, v ...interface{}) {
	l.write(fmt.Sprintf(format, v...))
}

func (l *capturingLogger) Print(v ...interface{}) {
	l.write(fmt.Sprint(v...))
}

func (l *capturingLogger) Println(v ...interface{}) {
	l.write(fmt.Sprintln(v...))
}

func (l *capturingLogger) write(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.WriteString(line)
	l.buf.WriteString("\n")
}

func (l *capturingLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestParseErrorDoesNotLogResponseBody verifies that when a response fails to
// parse, the raw body — which for this API can contain secret material — is not
// written to the configured logger.
func TestParseErrorDoesNotLogResponseBody(t *testing.T) {
	const marker = "SUPER-SECRET-VALUE-do-not-log"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"Name":"%s"`, marker)
	}))
	defer ts.Close()

	logger := &capturingLogger{}
	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := s.Secret(1); err == nil {
		t.Fatal("expected a parse error for the malformed response, got nil")
	}

	logged := logger.String()
	if strings.Contains(logged, marker) {
		t.Errorf("response body reached the logger despite a parse error:\n%s", logged)
	}
	if !strings.Contains(logged, "not logged") {
		t.Errorf("expected the parse-error log line to note the omitted body, got:\n%s", logged)
	}
}

// The write path logs its own parse error, and the body it declines to log is the
// secret that was just written.
func TestWriteParseErrorDoesNotLogResponseBody(t *testing.T) {
	const marker = "WRITTEN-SECRET-VALUE-do-not-log"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secret-templates/") {
			fmt.Fprint(w, `{"Name":"Web Password","ID":6,"Fields":[{"SecretTemplateFieldID":11,"FieldSlugName":"username"}]}`)
			return
		}
		fmt.Fprintf(w, `{"Name":"%s"`, marker)
	}))
	defer ts.Close()

	logger := &capturingLogger{}
	s, err := New(Configuration{
		ServerURL:   ts.URL,
		Credentials: UserCredential{Token: "pre-supplied-token"},
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if _, err := s.CreateSecret(Secret{SecretTemplateID: 6}); err == nil {
		t.Fatal("expected a parse error for the malformed write response, got nil")
	}

	logged := logger.String()
	if strings.Contains(logged, marker) {
		t.Errorf("written secret reached the logger despite a parse error:\n%s", logged)
	}
	if !strings.Contains(logged, "not logged") {
		t.Errorf("expected the parse-error log line to note the omitted body, got:\n%s", logged)
	}
}
