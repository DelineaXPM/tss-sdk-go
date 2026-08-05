package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// These cases run against a real server through runBattery, like the rest of the
// battery. They cover behavior that fixtures cannot honestly verify: what a real
// Secret Server does with an injected search term, what it returns for a secret that
// is not there, and whether the client-side limits in this package actually bite on a
// live connection.

// withConfig builds a second Server against the same target, with cfg applied. The
// battery's Server is left alone so a failure here cannot disturb later cases.
func withConfig(t *testing.T, tss *Server, apply func(*Configuration)) *Server {
	t.Helper()
	config := tss.Configuration
	apply(&config)
	s, err := New(config)
	if err != nil {
		t.Fatalf("building a Server variant: %v", err)
	}
	return s
}

// TestLiveTimeout is the Configuration.Timeout feature against a real connection: a
// timeout shorter than any real round trip must abort the request rather than hang.
func TestLiveTimeout(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")
		impatient := withConfig(t, tss, func(c *Configuration) { c.Timeout = time.Millisecond })

		if _, err := impatient.Secret(id); err == nil {
			t.Error("expected a 1ms timeout to abort the request, got no error")
		}

		// The same Server without a timeout still works, proving the failure was the
		// timeout rather than the credentials or the host.
		if _, err := tss.Secret(id); err != nil {
			t.Errorf("control request without a timeout failed: %v", err)
		}
	})
}

// TestLiveMaxResponseBytes is the response-size cap against a real response body.
func TestLiveMaxResponseBytes(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")
		capped := withConfig(t, tss, func(c *Configuration) { c.MaxResponseBytes = 100 })

		_, err := capped.Secret(id)
		if err == nil {
			t.Fatal("expected a 100-byte response cap to reject a real response, got no error")
		}
		if !strings.Contains(err.Error(), "exceeded") {
			t.Errorf("error = %q, want it to report the exceeded size limit", err)
		}
	})
}

// TestLiveTLSScopingRejectsUntrustedCA is the CWE-295 fix proving itself end to end: a
// per-Server TLS config with an empty trust store must fail against the real endpoint,
// while the process-global client still verifies that same endpoint normally — which
// is only possible if the config never reached http.DefaultTransport.
func TestLiveTLSScopingRejectsUntrustedCA(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")
		distrustful := withConfig(t, tss, func(c *Configuration) {
			c.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool()}
		})

		_, err := distrustful.Secret(id)
		if err == nil {
			t.Fatal("expected an empty trust store to reject the server certificate")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
			t.Errorf("error = %q, want a certificate verification failure", err)
		}

		// http.DefaultClient must be unaffected by the Server's TLS config.
		resp, err := http.DefaultClient.Get(tss.baseURL())
		if err != nil {
			t.Errorf("http.DefaultClient failed against %s after a Server used a custom trust store: %v",
				tss.baseURL(), err)
			return
		}
		resp.Body.Close()
	})
}

// TestLiveSearchTermIsNotInjected is Finding 1.2 against a real query parser: a search
// term carrying a query parameter must be matched literally, so it finds nothing,
// while the same term without the suffix still finds its secret. If the term were
// interpolated raw, the injected parameter would be parsed away and the search would
// match.
func TestLiveSearchTermIsNotInjected(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		searchText := requireEnv(t, "TSS_SEARCH_TEXT")

		clean, err := tss.Secrets(searchText, "")
		if err != nil {
			t.Fatalf("control search failed: %v", err)
		}
		if len(clean) == 0 {
			t.Fatalf("control search for %q matched nothing; the fixture cannot detect injection", searchText)
		}

		injected, err := tss.Secrets(searchText+"&paging.take=100000", "")
		if err != nil {
			// An error is an acceptable outcome; what matters is that it did not match.
			return
		}
		if len(injected) != 0 {
			t.Errorf("injected search term matched %d secrets; the term was not encoded as a literal value",
				len(injected))
		}
	})
}

// TestLiveMissingSecretReportsError checks that a real server's error response reaches
// the caller as an error rather than an empty secret.
func TestLiveMissingSecretReportsError(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		const absentID = 999999999

		secret, err := tss.Secret(absentID)
		if err == nil {
			t.Error("expected an error reading a secret that does not exist, got nil")
		}
		if secret != nil {
			t.Errorf("expected no secret for a missing id, got %+v", *secret)
		}
		if err != nil && err.Error() == "" {
			t.Error("the error carried no message from the server")
		}

		if err := tss.DeleteSecret(absentID); err == nil {
			t.Error("expected an error deleting a secret that does not exist, got nil")
		}
	})
}

// TestLiveTokenIsReusedAcrossCalls covers the cached-token lifetime: several calls in a
// row must be served by one grant. A re-authentication would replace the cached token,
// so an unchanged cache entry means the credentials were sent once.
func TestLiveTokenIsReusedAcrossCalls(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		tss.clearTokenCache()
		if _, err := tss.Secret(id); err != nil {
			t.Fatalf("first call failed: %v", err)
		}
		first, found := tss.getCacheAccessToken(tss.baseURL())
		if !found {
			t.Fatal("no token cached after a successful call")
		}

		for i := 0; i < 3; i++ {
			if _, err := tss.Secret(id); err != nil {
				t.Fatalf("call %d failed: %v", i+2, err)
			}
		}

		again, found := tss.getCacheAccessToken(tss.baseURL())
		if !found {
			t.Fatal("cached token disappeared during a run of successful calls")
		}
		if again != first {
			t.Error("the cached token changed across successive calls; the credentials were re-sent")
		}
	})
}

// TestLiveRejectedTokenIsEvictedAndRecovered is the eviction that bounds a cached
// token's useful life, against a real server. A token the server refuses must be
// dropped rather than replayed, so the call after a rejection re-authenticates and
// succeeds instead of failing forever.
func TestLiveRejectedTokenIsEvictedAndRecovered(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		// Seed a well-formed token the server will refuse, with a long life so it is
		// served from cache rather than treated as expired.
		if err := tss.setCacheAccessToken("not-a-valid-token", 3600, tss.baseURL()); err != nil {
			t.Fatalf("seeding the cache: %v", err)
		}
		if _, found := tss.getCacheAccessToken(tss.baseURL()); !found {
			t.Fatal("seeded token was not cached")
		}

		if _, err := tss.Secret(id); err == nil {
			t.Error("expected the rejected token to fail the request, got no error")
		}
		if _, found := tss.getCacheAccessToken(tss.baseURL()); found {
			t.Error("the rejected token survived in the cache; it must be evicted")
		}

		// Having evicted it, the SDK must recover on its own.
		if _, err := tss.Secret(id); err != nil {
			t.Errorf("the call after eviction did not re-authenticate: %v", err)
		}
	})
}

// TestLiveExpiredTokenIsRefreshed covers the other half of the cache's lifetime rule:
// an entry past its expiry must not be served, and the next call must obtain a new
// token rather than fail.
func TestLiveExpiredTokenIsRefreshed(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		// expiresIn of 0 puts the expiry at "now", so the entry is immediately stale.
		if err := tss.setCacheAccessToken("stale-token", 0, tss.baseURL()); err != nil {
			t.Fatalf("seeding the cache: %v", err)
		}
		if _, found := tss.getCacheAccessToken(tss.baseURL()); found {
			t.Fatal("an expired entry was served from the cache")
		}

		if _, err := tss.Secret(id); err != nil {
			t.Errorf("the call after expiry did not obtain a fresh token: %v", err)
		}
		if _, found := tss.getCacheAccessToken(tss.baseURL()); !found {
			t.Error("no token was cached after re-authenticating")
		}
	})
}

// TestLiveSuppliedTokenIsUsedAsIs covers the deployment where the caller already holds a
// token — obtained from a federated flow, a sidecar, or another vault — and passes it as
// Credentials.Token. That path diverges more than any other: getAccessToken returns
// immediately, so there is no health probe, no Platform discovery and no cache. It has
// only ever been exercised against httptest fixtures.
//
// Note what the Platform case establishes. Discovery is skipped, so the token must be
// presented to the vault that discovery would have found, not to the Platform URL. The
// token is taken here from a Server that has already discovered it, which is why the
// configuration copied below carries the vault address.
func TestLiveSuppliedTokenIsUsedAsIs(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		token, err := tss.getAccessToken()
		if err != nil {
			t.Fatalf("obtaining a token to re-supply: %v", err)
		}
		if token == "" {
			t.Fatal("obtained an empty token")
		}

		direct := withConfig(t, tss, func(c *Configuration) {
			c.Credentials = UserCredential{Token: token}
		})

		secret, err := direct.Secret(id)
		if err != nil {
			t.Fatalf("reading a secret with a caller-supplied token: %v", err)
		}
		if secret == nil || secret.ID != id {
			t.Errorf("supplied-token read returned %+v, want secret %d", secret, id)
		}
	})
}

// TestLiveTokenSharedAcrossServerInstances covers the shape a long-running consumer
// actually takes: a Server constructed per request or per reconcile, rather than one held
// for the process lifetime. The cache is package-level, so those instances should share a
// token instead of each authenticating. Only the collision case (different credentials
// must not share) was covered, and only as a unit test.
func TestLiveTokenSharedAcrossServerInstances(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		tss.clearTokenCache()
		if _, err := tss.Secret(id); err != nil {
			t.Fatalf("first instance failed: %v", err)
		}
		first, found := tss.getCacheAccessToken(tss.baseURL())
		if !found {
			t.Fatal("no token cached after the first instance authenticated")
		}

		// A separate Server with the same configuration, as a fresh reconcile would build.
		second := withConfig(t, tss, func(c *Configuration) {})
		if _, err := second.Secret(id); err != nil {
			t.Fatalf("second instance failed: %v", err)
		}

		again, found := second.getCacheAccessToken(second.baseURL())
		if !found {
			t.Fatal("the second instance did not see the cached token")
		}
		if again != first {
			t.Error("the second Server authenticated again instead of reusing the cached token")
		}
	})
}

// TestLiveConcurrentCallsShareOneToken covers concurrent use, which is how the importers
// of this SDK drive it — an operator reconciling many objects, a request handler serving
// many requests. It exercises the cache mutex against real latency rather than a fixture.
//
// The cache is warmed first, deliberately: with a cold cache each goroutine misses and
// sends its own grant, because getAccessToken checks and then authenticates without
// holding a lock across both. That is a known shape rather than a defect — every token is
// valid and the last write wins — and it is recorded as follow-up work rather than
// asserted here, since the count would be racy.
func TestLiveConcurrentCallsShareOneToken(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		if _, err := tss.Secret(id); err != nil {
			t.Fatalf("warming the cache failed: %v", err)
		}
		before, found := tss.getCacheAccessToken(tss.baseURL())
		if !found {
			t.Fatal("no token cached after warming")
		}

		const callers = 6
		var wg sync.WaitGroup
		failures := make(chan error, callers)
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := tss.Secret(id); err != nil {
					failures <- err
				}
			}()
		}
		wg.Wait()
		close(failures)

		for err := range failures {
			t.Errorf("concurrent call failed: %v", err)
		}

		after, found := tss.getCacheAccessToken(tss.baseURL())
		if !found {
			t.Error("the cached token disappeared during concurrent use")
		}
		if after != before {
			t.Error("concurrent calls replaced the cached token instead of sharing it")
		}
	})
}

// TestLiveGeneratePassword covers GeneratePassword against the real generate-password
// endpoint, which nothing did: the only coverage was fixtures returning bodies this test
// file chose. The parse of that body used to strip the first and last byte blindly, which
// is correct only for a password whose characters happen to need no JSON escaping — and
// the characters are chosen by the field's password requirements on the server, not here.
func TestLiveGeneratePassword(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		templateID := requireIntEnv(t, "TSS_TEMPLATE_ID")

		template, err := tss.SecretTemplate(templateID)
		if err != nil {
			t.Fatalf("reading template %d: %v", templateID, err)
		}
		var slug string
		for _, field := range template.Fields {
			if field.IsPassword {
				slug = field.FieldSlugName
				break
			}
		}
		if slug == "" {
			skipOrFailIntegration(t, "template %d (%s) has no password field to generate for", templateID, template.Name)
		}

		// Generated passwords are not printed on failure: they are credentials, even
		// unused ones, and this package exists to keep them out of process output.
		first, err := tss.GeneratePassword(slug, template)
		if err != nil {
			t.Fatalf("generating a password for the %q field: %v", slug, err)
		}
		if first == "" {
			t.Fatal("the server generated an empty password")
		}
		if strings.HasPrefix(first, `"`) || strings.HasSuffix(first, `"`) {
			t.Error("the generated password still carries the JSON quoting of the response")
		}

		second, err := tss.GeneratePassword(slug, template)
		if err != nil {
			t.Fatalf("generating a second password: %v", err)
		}
		if second == first {
			t.Error("two generate-password calls returned the same password")
		}

		if _, err := tss.GeneratePassword("tss-sdk-go-no-such-field", template); err == nil {
			t.Error("expected a slug that names no field to be rejected, got no error")
		}
	})
}

// TestLiveSecretMaterialIsNotLogged installs a logger for one real read and inspects what
// it received. The redaction fix is pinned by fixtures on the parse-error path only, and
// with a logger that records its arguments; the ordinary successful path — where the
// values in play are a real secret's own, and every request logs its URL — was unchecked.
func TestLiveSecretMaterialIsNotLogged(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		id := requireIntEnv(t, "TSS_SECRET_ID")

		logger := &capturingLogger{}
		verbose := withConfig(t, tss, func(c *Configuration) { c.Logger = logger })

		secret, err := verbose.Secret(id)
		if err != nil {
			t.Fatalf("reading secret %d: %v", id, err)
		}

		output := logger.String()
		if output == "" {
			t.Fatal("the logger recorded nothing, so this case cannot detect a leak")
		}

		checked := 0
		for _, field := range secret.Fields {
			// Short values collide with ordinary log text, and a value that is part of
			// the address being logged is the address rather than the secret leaking.
			if len(field.ItemValue) < 8 || strings.Contains(verbose.baseURL(), field.ItemValue) {
				continue
			}
			checked++
			if strings.Contains(output, field.ItemValue) {
				t.Errorf("the value of field %q reached the logger", field.Slug)
			}
		}
		if checked == 0 {
			skipOrFailIntegration(t, "the fixture secret has no field value long enough to detect in a log")
		}

		if token, found := tss.getCacheAccessToken(tss.baseURL()); found && strings.Contains(output, token) {
			t.Error("the access token reached the logger")
		}
	})
}

// TestLiveUnknownEndpointIsDiagnosed points a Server at a real host that answers but is
// neither a Secret Server nor a Platform. Every such failure used to reach the caller as
// "invalid URL", with the actual probe results going only to the logger; the error must
// now name what was probed. Only the same host the battery is already configured for is
// used, so the case introduces no dependency on an outside address.
func TestLiveUnknownEndpointIsDiagnosed(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		base := strings.TrimRight(tss.baseURL(), "/") + "/tss-sdk-go-not-a-secret-server"
		wrong := withConfig(t, tss, func(c *Configuration) {
			c.ServerURL = base
			// New rejects a Configuration carrying both, and a tenant-configured
			// battery would otherwise still derive its own base URL.
			c.Tenant = ""
		})

		_, err := wrong.Secret(1)
		if err == nil {
			t.Fatal("expected an error against a URL hosting neither a Secret Server nor a Platform")
		}
		for _, probe := range []string{base + "/api/v1/healthcheck", base + "/health"} {
			if !strings.Contains(err.Error(), probe) {
				t.Errorf("error %q does not name the probed URL %s", err, probe)
			}
		}
		if strings.Contains(err.Error(), "invalid URL") {
			t.Errorf("error still reports the fabricated cause: %v", err)
		}
	})
}

// TestLiveMissingSecretPathReportsError is the path lookup's answer for something that is
// not there. TestLiveMissingSecretReportsError covers the same question for an id, and the
// two go through different endpoints: a path miss must be an error rather than the zero
// secret, which a caller would read as a secret with no fields.
func TestLiveMissingSecretPathReportsError(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		folder := folderPathOf(t, requireEnv(t, "TSS_SECRET_PATH"))

		secret, err := tss.SecretByPath(folder + `\tss-sdk-go-no-such-secret`)
		if err == nil {
			t.Error("expected an error reading a secret path that does not exist, got nil")
		}
		if secret != nil {
			t.Errorf("expected no secret for a missing path, got %+v", *secret)
		}
	})
}

// folderPathOf returns the folder portion of the configured secret path, which is the
// folder the battery's fixtures live in.
func folderPathOf(t *testing.T, secretPath string) string {
	t.Helper()
	i := strings.LastIndexAny(secretPath, `\/`)
	if i <= 0 {
		skipOrFailIntegration(t, "cannot derive a folder from the configured secret path %q", secretPath)
	}
	return secretPath[:i]
}

func TestFolderPathOfSupportsPlatformAndSecretServerSeparators(t *testing.T) {
	for path, want := range map[string]string{
		`/Platform Folder/Secret`: `/Platform Folder`,
		`\Secret Server\Secret`:   `\Secret Server`,
		`/Nested/Folder/Secret`:   `/Nested/Folder`,
		`\Nested\Folder\Secret`:   `\Nested\Folder`,
	} {
		if got := folderPathOf(t, path); got != want {
			t.Errorf("folderPathOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestLiveSecretPathWithSpecialCharacters covers the path encoding on a real server.
// The existing fixture paths are alphanumeric, so they never exercise it: this creates
// a secret whose name carries a space and an ampersand, reads it back by path, and
// removes it.
func TestLiveSecretPathWithSpecialCharacters(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		folderID := requireIntEnv(t, "TSS_FOLDER_ID")
		siteID := requireIntEnv(t, "TSS_SITE_ID")
		templateID := requireIntEnv(t, "TSS_TEMPLATE_ID")
		folder := folderPathOf(t, requireEnv(t, "TSS_SECRET_PATH"))
		password := requireEnv(t, "TSS_TEST_PASSWORD")

		template, err := tss.SecretTemplate(templateID)
		if err != nil {
			t.Fatalf("reading template %d: %v", templateID, err)
		}

		const name = `battery path & spaces`
		secret := Secret{
			Name:             name,
			SiteID:           siteID,
			FolderID:         folderID,
			SecretTemplateID: templateID,
			Fields:           requiredFieldsFor(t, template, password, false),
		}

		created, err := tss.CreateSecret(secret)
		if err != nil {
			t.Fatalf("creating a secret named %q: %v", name, err)
		}
		deleteAfterTest(t, tss, created.ID)

		found, err := tss.SecretByPath(folder + `\` + name)
		if err != nil {
			t.Fatalf("reading %q by path: %v", folder+`\`+name, err)
		}
		if found.ID != created.ID {
			t.Errorf("path lookup returned secret %d, want %d", found.ID, created.ID)
		}
		if found.Name != name {
			t.Errorf("path lookup returned name %q, want %q", found.Name, name)
		}
	})
}

// TestLiveFileFieldDeletion covers the branch of updateFiles that removes an
// attachment: clearing a file field's value must delete the file rather than upload an
// empty one. Getting this wrong destroys an attachment silently, so it is checked
// against a real server.
func TestLiveFileFieldDeletion(t *testing.T) {
	runBattery(t, func(t *testing.T, tss *Server) {
		folderID := requireIntEnv(t, "TSS_FOLDER_ID")
		siteID := requireIntEnv(t, "TSS_SITE_ID")
		templateID := requireIntEnv(t, "TSS_SSH_KEY_TEMPLATE_ID")

		template, err := tss.SecretTemplate(templateID)
		if err != nil {
			t.Fatalf("reading template %d: %v", templateID, err)
		}
		var fileSlug string
		for _, field := range template.Fields {
			if field.IsFile && strings.Contains(strings.ToLower(field.FieldSlugName), "public") {
				fileSlug = field.FieldSlugName
				break
			}
		}
		if fileSlug == "" {
			skipOrFailIntegration(t, "template %d has no public-key file field to clear", templateID)
		}

		created, err := tss.CreateSecret(Secret{
			Name:             "battery file deletion",
			SiteID:           siteID,
			FolderID:         folderID,
			SecretTemplateID: templateID,
			SshKeyArgs:       &SshKeyArgs{GenerateSshKeys: true, GeneratePassphrase: true},
			Fields:           requiredFieldsFor(t, template, requireEnv(t, "TSS_TEST_PASSWORD"), true),
		})
		if err != nil {
			t.Fatalf("creating an SSH secret: %v", err)
		}
		deleteAfterTest(t, tss, created.ID)

		before := fieldBySlug(created, fileSlug)
		if before == nil || len(before.ItemValue) == 0 || before.Filename == "" {
			t.Fatalf("field %q has no generated file to delete", fileSlug)
		}
		originalValue := before.ItemValue

		for i, field := range created.Fields {
			if field.Slug == fileSlug {
				created.Fields[i].ItemValue = ""
			}
		}
		if _, err := tss.UpdateSecret(*created); err != nil {
			t.Fatalf("clearing the file field: %v", err)
		}

		reread, err := tss.Secret(created.ID)
		if err != nil {
			t.Fatalf("re-reading after clearing the file field: %v", err)
		}
		after := fieldBySlug(reread, fileSlug)
		if after == nil {
			t.Fatalf("field %q disappeared from the secret entirely", fileSlug)
		}
		// Secret Server keeps the field and its attachment id but clears the filename,
		// and returns "*** Not Valid For Display ***" where contents would be. The
		// filename is therefore what says whether the file is really gone.
		if after.Filename != "" {
			t.Errorf("field %q still has filename %q after being cleared; the attachment survived",
				fileSlug, after.Filename)
		}
		if after.ItemValue == originalValue {
			t.Errorf("field %q still returns its original contents after being cleared", fileSlug)
		}
	})
}

// fieldBySlug returns a whole field, where Secret.Field returns only its value.
func fieldBySlug(secret *Secret, slug string) *SecretField {
	for i, field := range secret.Fields {
		if field.Slug == slug {
			return &secret.Fields[i]
		}
	}
	return nil
}

// requiredFieldsFor fills every required field of a template, as SecretCRUD does. When
// filesGenerated is true the caller has asked the server to generate the file fields
// (SSH keys), so those are left out rather than treated as an obstacle.
func requiredFieldsFor(t *testing.T, template *SecretTemplate, password string, filesGenerated bool) []SecretField {
	t.Helper()
	var fields []SecretField
	for _, field := range template.Fields {
		value := ""
		switch {
		case field.IsFile:
			if field.IsRequired && !filesGenerated {
				skipOrFailIntegration(t, "template %d requires the file field %q, which this case cannot generate",
					template.ID, field.FieldSlugName)
			}
		case field.IsPassword:
			value = password
		case strings.Contains(strings.ToLower(field.FieldSlugName), "username"):
			value = "TestUser"
		case strings.Contains(strings.ToLower(field.FieldSlugName), "machine"),
			strings.Contains(strings.ToLower(field.FieldSlugName), "host"):
			value = "test.example.com"
		case field.IsRequired:
			value = "test-" + field.FieldSlugName
		}
		if value != "" {
			fields = append(fields, SecretField{FieldID: field.SecretTemplateFieldID, ItemValue: value})
		}
	}
	if len(fields) == 0 {
		t.Fatalf("template %s (%d) yielded no usable fields", template.Name, template.ID)
	}
	return fields
}
