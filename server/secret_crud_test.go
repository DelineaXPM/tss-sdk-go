package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type recordedRequest struct {
	method      string
	path        string
	rawQuery    string
	contentType string
	body        string
}

type fixture struct {
	server   *httptest.Server
	client   *Server
	requests []recordedRequest
}

// newFixture stands up a Secret Server whose routes are supplied by the caller, paired
// with a Server that authenticates with a pre-supplied token so no grant round trip is
// needed. Every request is recorded for assertions.
func newFixture(t *testing.T, routes func(w http.ResponseWriter, r *http.Request)) *fixture {
	t.Helper()
	f := &fixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		f.requests = append(f.requests, recordedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			rawQuery:    r.URL.RawQuery,
			contentType: r.Header.Get("Content-Type"),
			body:        string(body),
		})
		routes(w, r)
	}))
	t.Cleanup(f.server.Close)

	client, err := New(Configuration{
		ServerURL:   f.server.URL,
		Credentials: UserCredential{Token: "test-token"},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	f.client = client
	return f
}

func (f *fixture) find(t *testing.T, method, path string) recordedRequest {
	t.Helper()
	for _, req := range f.requests {
		if req.method == method && req.path == path {
			return req
		}
	}
	t.Fatalf("no %s request to %q; recorded: %+v", method, path, f.requests)
	return recordedRequest{}
}

const secretWithAttachment = `{"Name":"My Secret","ID":1,"SecretTemplateID":6,"Items":[
	{"FieldID":13,"Slug":"attachment","IsFile":true,"FileAttachmentID":9,"Filename":"f.txt","ItemValue":"dummy"},
	{"FieldID":11,"Slug":"username","ItemValue":"bob"}
]}`

// A file field's dummy ItemValue must be replaced by the downloaded attachment content,
// transparently to the caller.
func TestSecretDownloadsFileAttachment(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/fields/attachment") {
			fmt.Fprint(w, "FILE-CONTENTS")
			return
		}
		fmt.Fprint(w, secretWithAttachment)
	})

	secret, err := f.client.Secret(1)
	if err != nil {
		t.Fatalf("Secret returned error: %v", err)
	}

	if got, _ := secret.Field("attachment"); got != "FILE-CONTENTS" {
		t.Errorf("attachment field = %q, want the downloaded content %q", got, "FILE-CONTENTS")
	}
	if got, _ := secret.Field("username"); got != "bob" {
		t.Errorf("username field = %q, want %q", got, "bob")
	}
	f.find(t, "GET", "/api/v1/secrets/1/fields/attachment")
}

// A file field with no attachment ID must not trigger a download.
func TestSecretSkipsFileFieldWithoutAttachment(t *testing.T) {
	const noAttachment = `{"Name":"My Secret","ID":1,"Items":[
		{"Slug":"attachment","IsFile":true,"FileAttachmentID":0,"Filename":"f.txt","ItemValue":"placeholder"}
	]}`
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, noAttachment)
	})

	secret, err := f.client.Secret(1)
	if err != nil {
		t.Fatalf("Secret returned error: %v", err)
	}
	if got, _ := secret.Field("attachment"); got != "placeholder" {
		t.Errorf("attachment field = %q, want the value left untouched", got)
	}
	if len(f.requests) != 1 {
		t.Errorf("made %d requests, want 1 (no attachment download)", len(f.requests))
	}
}

func TestSecretByPathEncodesSecretPath(t *testing.T) {
	const secretPath = "/Personal/admin/My Secret&x=1"
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Name":"My Secret","ID":1,"Items":[]}`)
	})

	if _, err := f.client.SecretByPath(secretPath); err != nil {
		t.Fatalf("SecretByPath returned error: %v", err)
	}

	req := f.requests[0]
	values, err := url.ParseQuery(req.rawQuery)
	if err != nil {
		t.Fatalf("unparseable query %q: %v", req.rawQuery, err)
	}
	if got := values.Get("secretPath"); got != secretPath {
		t.Errorf("secretPath = %q, want %q (it should survive encoding intact)", got, secretPath)
	}
}

// Search results are not fully populated, so each record is re-fetched by ID.
func TestSecretsSearchFetchesFullRecords(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			fmt.Fprint(w, `{"SearchText":"term","Records":[{"ID":1},{"ID":2}]}`)
		case "/api/v1/secrets/1":
			fmt.Fprint(w, `{"Name":"first","ID":1,"Items":[]}`)
		case "/api/v1/secrets/2":
			fmt.Fprint(w, `{"Name":"second","ID":2,"Items":[]}`)
		default:
			http.NotFound(w, r)
		}
	})

	secrets, err := f.client.Secrets("term", "")
	if err != nil {
		t.Fatalf("Secrets returned error: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want 2", len(secrets))
	}
	if secrets[0].Name != "first" || secrets[1].Name != "second" {
		t.Errorf("names = %q, %q; want the fully fetched records", secrets[0].Name, secrets[1].Name)
	}
}

func TestDeleteSecretIssuesDeleteRequest(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})

	if err := f.client.DeleteSecret(42); err != nil {
		t.Fatalf("DeleteSecret returned error: %v", err)
	}
	f.find(t, "DELETE", "/api/v1/secrets/42")
}

// SSH key generation is only valid on creation; UpdateSecret must reject it before
// sending anything.
func TestUpdateSecretRejectsSshKeyGeneration(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})

	secret := Secret{ID: 1, SecretTemplateID: 6, SshKeyArgs: &SshKeyArgs{GenerateSshKeys: true}}
	if _, err := f.client.UpdateSecret(secret); err == nil {
		t.Error("UpdateSecret accepted SSH key generation, want an error")
	}
	if len(f.requests) != 0 {
		t.Errorf("made %d requests, want 0 for a rejected update", len(f.requests))
	}
}

const templateJSON = `{"Name":"Web Password","ID":6,"Fields":[
	{"SecretTemplateFieldID":11,"FieldSlugName":"username"},
	{"SecretTemplateFieldID":13,"FieldSlugName":"attachment","IsFile":true}
]}`

func TestSecretTemplateFetch(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, templateJSON)
	})

	template, err := f.client.SecretTemplate(6)
	if err != nil {
		t.Fatalf("SecretTemplate returned error: %v", err)
	}
	if template.Name != "Web Password" || len(template.Fields) != 2 {
		t.Errorf("template = %+v, want the parsed Web Password template with 2 fields", *template)
	}
	f.find(t, "GET", "/api/v1/secret-templates/6")
}

// A secret with no fields must still send an empty Items array; omitting it makes the
// server reject the request for a missing required element.
func TestCreateSecretSendsEmptyItemsWhenNoFields(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/secret-templates/"):
			fmt.Fprint(w, templateJSON)
		case r.Method == "POST":
			fmt.Fprint(w, `{"Name":"created","ID":7,"Items":[]}`)
		default:
			fmt.Fprint(w, `{"Name":"created","ID":7,"Items":[]}`)
		}
	})

	if _, err := f.client.CreateSecret(Secret{SecretTemplateID: 6}); err != nil {
		t.Fatalf("CreateSecret returned error: %v", err)
	}

	post := f.find(t, "POST", "/api/v1/secrets/")
	if !strings.Contains(post.body, `"Items":[]`) {
		t.Errorf("POST body = %s, want it to carry an empty Items array", post.body)
	}
	if post.contentType != "application/json" {
		t.Errorf("POST Content-Type = %q, want application/json", post.contentType)
	}
}

// An emptied file field is deleted with a PATCH rather than uploaded.
func TestUpdateFilesDeletesFieldWithEmptyValue(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})

	if err := f.client.updateFiles(1, []SecretField{{Slug: "attachment", ItemValue: ""}}); err != nil {
		t.Fatalf("updateFiles returned error: %v", err)
	}

	patch := f.find(t, "PATCH", "/api/v1/secrets/1/general")
	for _, want := range []string{`"Slug":"attachment"`, `"Dirty":true`, `"Value":null`} {
		if !strings.Contains(patch.body, want) {
			t.Errorf("PATCH body = %s, want it to contain %s", patch.body, want)
		}
	}
}

func TestUpdateFilesUploadsFieldWithValue(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})

	field := SecretField{Slug: "attachment", Filename: "notes.txt", ItemValue: "file body"}
	if err := f.client.updateFiles(1, []SecretField{field}); err != nil {
		t.Fatalf("updateFiles returned error: %v", err)
	}

	put := f.find(t, "PUT", "/api/v1/secrets/1/fields/attachment")
	if !strings.HasPrefix(put.contentType, "multipart/form-data") {
		t.Errorf("PUT Content-Type = %q, want multipart/form-data", put.contentType)
	}
	if !strings.Contains(put.body, "file body") {
		t.Errorf("PUT body did not carry the field value: %s", put.body)
	}
}

func TestUpdateSecretSendsPutToSecretID(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secret-templates/") {
			fmt.Fprint(w, templateJSON)
			return
		}
		fmt.Fprint(w, `{"Name":"updated","ID":7,"Items":[]}`)
	})

	updated, err := f.client.UpdateSecret(Secret{ID: 7, SecretTemplateID: 6})
	if err != nil {
		t.Fatalf("UpdateSecret returned error: %v", err)
	}
	if updated.Name != "updated" {
		t.Errorf("name = %q, want %q", updated.Name, "updated")
	}
	f.find(t, "PUT", "/api/v1/secrets/7")
}

// An SshKeyArgs with nothing enabled is dropped: merely sending the element makes the
// server reject templates that are not geared to SSH key generation.
func TestCreateSecretDropsEmptySshKeyArgs(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secret-templates/") {
			fmt.Fprint(w, templateJSON)
			return
		}
		fmt.Fprint(w, `{"Name":"created","ID":7,"Items":[]}`)
	})

	secret := Secret{SecretTemplateID: 6, SshKeyArgs: &SshKeyArgs{}}
	if _, err := f.client.CreateSecret(secret); err != nil {
		t.Fatalf("CreateSecret returned error: %v", err)
	}

	post := f.find(t, "POST", "/api/v1/secrets/")
	if strings.Contains(post.body, "SshKeyArgs") {
		t.Errorf("POST body = %s, want SshKeyArgs omitted when neither generation flag is set", post.body)
	}
}

func TestCreateSecretKeepsRequestedSshKeyArgs(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secret-templates/") {
			fmt.Fprint(w, templateJSON)
			return
		}
		fmt.Fprint(w, `{"Name":"created","ID":7,"Items":[]}`)
	})

	secret := Secret{SecretTemplateID: 6, SshKeyArgs: &SshKeyArgs{GenerateSshKeys: true}}
	if _, err := f.client.CreateSecret(secret); err != nil {
		t.Fatalf("CreateSecret returned error: %v", err)
	}

	post := f.find(t, "POST", "/api/v1/secrets/")
	if !strings.Contains(post.body, `"GenerateSshKeys":true`) {
		t.Errorf("POST body = %s, want the requested SSH key generation preserved", post.body)
	}
}

// SecretByPath downloads attachments just as Secret does.
func TestSecretByPathDownloadsFileAttachment(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/fields/attachment") {
			fmt.Fprint(w, "PATH-FILE-CONTENTS")
			return
		}
		fmt.Fprint(w, secretWithAttachment)
	})

	secret, err := f.client.SecretByPath("/Personal/admin/My Secret")
	if err != nil {
		t.Fatalf("SecretByPath returned error: %v", err)
	}
	if got, _ := secret.Field("attachment"); got != "PATH-FILE-CONTENTS" {
		t.Errorf("attachment field = %q, want the downloaded content", got)
	}
}

// A malformed response must surface as an error rather than a zero-valued result.
func TestSecretTemplateRejectsUnparseableResponse(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	})

	if _, err := f.client.SecretTemplate(6); err == nil {
		t.Error("expected an error for an unparseable template response, got nil")
	}
}

func TestSecretRejectsUnparseableResponse(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	})

	if _, err := f.client.Secret(1); err == nil {
		t.Error("expected an error for an unparseable secret response, got nil")
	}
	if _, err := f.client.Secrets("term", ""); err == nil {
		t.Error("expected an error for an unparseable search response, got nil")
	}
	if _, err := f.client.SecretByPath("/x"); err == nil {
		t.Error("expected an error for an unparseable secret-by-path response, got nil")
	}
}

// An error from the server must propagate rather than yield a partial secret.
func TestSecretPropagatesServerError(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"errorCode":"boom"}`)
	})

	if _, err := f.client.Secret(1); err == nil {
		t.Error("expected the server error to propagate from Secret, got nil")
	}
	if err := f.client.DeleteSecret(1); err == nil {
		t.Error("expected the server error to propagate from DeleteSecret, got nil")
	}
	if _, err := f.client.CreateSecret(Secret{SecretTemplateID: 6}); err == nil {
		t.Error("expected the server error to propagate from CreateSecret, got nil")
	}
}

// uploadFile supplies a filename the server will accept: absent entirely, or lacking an
// extension, it is given one.
func TestUploadFileNormalizesFilename(t *testing.T) {
	for _, c := range []struct{ filename, want string }{
		{"", "File.txt"},
		{"notes", "notes.txt"},
		{"notes.md", "notes.md"},
	} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{}`)
		})

		field := SecretField{Slug: "attachment", Filename: c.filename, ItemValue: "body"}
		if err := f.client.uploadFile(1, field); err != nil {
			t.Fatalf("uploadFile(%q) returned error: %v", c.filename, err)
		}

		put := f.find(t, "PUT", "/api/v1/secrets/1/fields/attachment")
		if want := fmt.Sprintf(`filename="%s"`, c.want); !strings.Contains(put.body, want) {
			t.Errorf("uploadFile(%q) sent body %s, want it to contain %s", c.filename, put.body, want)
		}
	}
}
