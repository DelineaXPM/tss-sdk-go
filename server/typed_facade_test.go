package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func tokenServer(t *testing.T, handler http.Handler) (*Server, *httptest.Server) {
	t.Helper()
	testServer := httptest.NewServer(handler)
	t.Cleanup(testServer.Close)
	client, err := New(Configuration{
		ServerURL:      testServer.URL,
		Credentials:    UserCredential{Token: "typed-contract-token"},
		DisableRetries: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, testServer
}

func TestFacadeSearchAndPathQueryContracts(t *testing.T) {
	var mu sync.Mutex
	var searchQuery, pathQuery string
	client, _ := tokenServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			mu.Lock()
			searchQuery = r.URL.RawQuery
			mu.Unlock()
			fmt.Fprint(w, `{"Records":[]}`)
		case "/api/v1/secrets/0":
			mu.Lock()
			pathQuery = r.URL.RawQuery
			mu.Unlock()
			fmt.Fprint(w, `{"ID":13,"Name":"by path","Items":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	searchText := "literal&paging.take=999"
	if _, err := client.Secrets(searchText, "Name"); err != nil {
		t.Fatal(err)
	}
	secretPath := `\folder\name & value`
	if _, err := client.SecretByPath(secretPath); err != nil {
		t.Fatal(err)
	}
	searchRequest, _ := http.NewRequest(http.MethodGet, "http://example/?"+searchQuery, nil)
	if got := searchRequest.URL.Query().Get("paging.filter.searchText"); got != searchText {
		t.Fatalf("search text=%q", got)
	}
	if got := searchRequest.URL.Query().Get("paging.take"); got != "30" {
		t.Fatalf("paging.take=%q", got)
	}
	pathRequest, _ := http.NewRequest(http.MethodGet, "http://example/?"+pathQuery, nil)
	if got := pathRequest.URL.Query().Get("secretPath"); got != secretPath {
		t.Fatalf("secretPath=%q", got)
	}
}

func TestFacadeTypedCRUDContracts(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	record := func(r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
	}
	client, _ := tokenServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secret-templates/10":
			fmt.Fprint(w, `{"ID":10,"Name":"Account","Fields":[{"SecretTemplateFieldID":1,"FieldSlugName":"username"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/":
			var secret Secret
			if err := json.NewDecoder(r.Body).Decode(&secret); err != nil {
				t.Error(err)
			}
			if secret.Name != "created" || len(secret.Fields) != 1 {
				t.Errorf("create body=%+v", secret)
			}
			fmt.Fprint(w, `{"ID":21}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/21":
			fmt.Fprint(w, `{"ID":21}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/21":
			fmt.Fprint(w, `{"ID":21,"Name":"created","SecretTemplateID":10,"Items":[{"FieldID":1,"Slug":"username","ItemValue":"alice"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/21":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	input := Secret{
		Name: "created", SecretTemplateID: 10,
		Fields: []SecretField{{FieldID: 1, ItemValue: "alice"}},
	}
	created, err := client.CreateSecret(input)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != 21 {
		t.Fatalf("created ID=%d", created.ID)
	}
	input.ID = 21
	if _, err := client.UpdateSecret(input); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteSecret(21); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{
		"POST /api/v1/secrets/", "PUT /api/v1/secrets/21", "DELETE /api/v1/secrets/21",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("calls missing %q:\n%s", want, joined)
		}
	}
}

func TestFacadeMultipartAndGeneratedPasswordContracts(t *testing.T) {
	client, _ := tokenServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/22/fields/private-key":
			if r.Method != http.MethodPut {
				t.Errorf("method=%s", r.Method)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Error(err)
				return
			}
			defer file.Close()
			body, _ := io.ReadAll(file)
			if header.Filename != "key.txt" || string(body) != "private material" {
				t.Errorf("filename=%q body=%q", header.Filename, body)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/secret-templates/generate-password/5":
			fmt.Fprint(w, `"p\\\"w"`)
		default:
			http.NotFound(w, r)
		}
	}))
	if err := client.uploadFile(22, SecretField{Slug: "private-key", Filename: "key", ItemValue: "private material"}); err != nil {
		t.Fatal(err)
	}
	template := &SecretTemplate{Name: "Password", Fields: []SecretTemplateField{{SecretTemplateFieldID: 5, FieldSlugName: "password"}}}
	password, err := client.GeneratePassword("password", template)
	if err != nil {
		t.Fatal(err)
	}
	if password != `p\"w` {
		t.Fatalf("password=%q", password)
	}
}
