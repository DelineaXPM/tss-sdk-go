package server

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A Secret Server Cloud tenant derives its base URL from Tenant/TLD rather than
// ServerURL; the cache must key and clear on that derived URL.
func TestTokenCacheForCloudTenant(t *testing.T) {
	s, err := New(Configuration{Tenant: "acme", Credentials: UserCredential{Username: "ivy"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	cloudURL := fmt.Sprintf(cloudBaseURLTemplate, "acme", defaultTLD)

	if err := s.setCacheAccessToken("cloud-token", 3600, cloudURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}
	if got, ok := s.getCacheAccessToken(cloudURL); !ok || got != "cloud-token" {
		t.Fatalf("cloud cache = (%q, %v), want (%q, true)", got, ok, "cloud-token")
	}

	s.clearTokenCache()

	if _, ok := s.getCacheAccessToken(cloudURL); ok {
		t.Error("clearTokenCache did not evict the entry for a cloud tenant")
	}
}

// TestTokenCacheNotStoredInEnvironment is the CWE-526 regression: a cached access
// token must live in process memory only and must never be written to the process
// environment (where it would leak to child processes and any reader of /proc).
func TestTokenCacheNotStoredInEnvironment(t *testing.T) {
	const (
		serverURL = "https://cache-env.example.com"
		token     = "test-bearer-token-value-cwe526"
	)
	s, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "alice"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := s.setCacheAccessToken(token, 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}

	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SS_AT_") {
			t.Errorf("token cache leaked into environment: %s", kv)
		}
		if strings.Contains(kv, token) {
			t.Errorf("cached token value found in environment variable: %s", kv)
		}
	}

	got, ok := s.getCacheAccessToken(serverURL)
	if !ok {
		t.Fatal("expected in-memory cached token to be retrievable")
	}
	if got != token {
		t.Errorf("cached token = %q, want %q", got, token)
	}
}

// TestClearTokenCacheRemovesEntry verifies the in-memory entry is evicted on clear.
func TestClearTokenCacheRemovesEntry(t *testing.T) {
	const serverURL = "https://cache-clear.example.com"
	s, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "bob"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := s.setCacheAccessToken("tok", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}
	s.clearTokenCache()

	if _, ok := s.getCacheAccessToken(serverURL); ok {
		t.Error("expected token cache to be empty after clearTokenCache")
	}
}

// TestTokenCacheExpiredEntryNotServed verifies the expiry check survived the move to
// the in-memory store: an entry past its expiry is not returned.
func TestTokenCacheExpiredEntryNotServed(t *testing.T) {
	const serverURL = "https://cache-expiry.example.com"
	s, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "dave"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	// expiresIn of 0 yields an expiry of "now", so the entry is immediately stale.
	if err := s.setCacheAccessToken("stale-token", 0, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}

	if _, ok := s.getCacheAccessToken(serverURL); ok {
		t.Error("expected an expired cache entry not to be served")
	}
}

// A miss must evict only the key that was looked up. Keying the eviction on the current
// base URL instead would, after Platform discovery rewrites ServerURL, drop the vault's
// live token whenever a stale entry under the old URL is queried.
func TestTokenCacheMissEvictsOnlyTheQueriedKey(t *testing.T) {
	const platformURL = "https://cache-miss.example.com"
	const vaultURL = "https://cache-miss-vault.example.com"
	s, err := New(Configuration{ServerURL: platformURL, Credentials: UserCredential{Username: "gina"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := s.setCacheAccessToken("vault-token", 3600, vaultURL); err != nil {
		t.Fatalf("setCacheAccessToken (vault) returned error: %v", err)
	}
	// Seeded last: setCacheAccessToken sweeps entries that are already expired, and
	// this one must still be in the map when the lookup below misses on it.
	if err := s.setCacheAccessToken("expired-token", 0, platformURL); err != nil {
		t.Fatalf("setCacheAccessToken (platform) returned error: %v", err)
	}
	s.ServerURL = vaultURL

	if _, ok := s.getCacheAccessToken(platformURL); ok {
		t.Fatal("an expired entry was served from the cache")
	}

	tokenCacheMu.Lock()
	_, expiredRemains := tokenCache[s.cacheKey(platformURL)]
	tokenCacheMu.Unlock()
	if expiredRemains {
		t.Error("the expired entry survived the miss that found it")
	}

	if got, ok := s.getCacheAccessToken(vaultURL); !ok || got != "vault-token" {
		t.Errorf("vault cache = (%q, %v), want (%q, true); the miss evicted the wrong key", got, ok, "vault-token")
	}
}

// Expired entries are otherwise deleted only when their exact key is queried again, and
// a key embeds the credential digest, so entries orphaned by a password rotation would
// grow the package-level map for the life of the process.
func TestSetCacheAccessTokenSweepsExpiredEntries(t *testing.T) {
	const serverURL = "https://cache-sweep.example.com"
	rotated := credentialServer(t, serverURL, "", "admin", "old-password")
	current := credentialServer(t, serverURL, "", "admin", "new-password")

	if err := rotated.setCacheAccessToken("stale-token", 0, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (rotated) returned error: %v", err)
	}
	if err := current.setCacheAccessToken("fresh-token", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (current) returned error: %v", err)
	}

	tokenCacheMu.Lock()
	_, orphanRemains := tokenCache[rotated.cacheKey(serverURL)]
	tokenCacheMu.Unlock()
	if orphanRemains {
		t.Error("the expired entry for the rotated password survived a later set")
	}

	if got, ok := current.getCacheAccessToken(serverURL); !ok || got != "fresh-token" {
		t.Errorf("current cache = (%q, %v), want (%q, true)", got, ok, "fresh-token")
	}
}

// TestTokenCacheKeyedByCredentials locks in the PBI 693137 collision fix: two Servers
// sharing a ServerURL but using different usernames must not share cached tokens.
func TestTokenCacheKeyedByCredentials(t *testing.T) {
	const serverURL = "https://cache-collision.example.com"
	serverA, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "userA"}})
	if err != nil {
		t.Fatalf("New (A) returned error: %v", err)
	}
	serverB, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "userB"}})
	if err != nil {
		t.Fatalf("New (B) returned error: %v", err)
	}

	if err := serverA.setCacheAccessToken("token-for-A", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (A) returned error: %v", err)
	}

	if _, ok := serverB.getCacheAccessToken(serverURL); ok {
		t.Error("userB retrieved a token cached under userA; per-username keying regressed")
	}

	got, ok := serverA.getCacheAccessToken(serverURL)
	if !ok || got != "token-for-A" {
		t.Errorf("userA cache = (%q, %v), want (%q, true)", got, ok, "token-for-A")
	}
}

// TestTokenCacheRetainedForMostOfLifetime pins the expiry formula: a token must be
// served from cache for ~90% of its lifetime, not re-fetched after 10% of it (the
// previous formula subtracted the wrong side of the safety margin).
func TestTokenCacheRetainedForMostOfLifetime(t *testing.T) {
	const serverURL = "https://cache-lifetime.example.com"
	s, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "erin"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if err := s.setCacheAccessToken("tok", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken returned error: %v", err)
	}

	tokenCacheMu.Lock()
	cache := tokenCache[s.cacheKey(serverURL)]
	tokenCacheMu.Unlock()

	now := time.Now().Unix()
	if expiry := int64(cache.ExpiresIn); expiry < now+3000 || expiry > now+3600 {
		t.Errorf("cache expiry = now+%ds, want between now+3000s and now+3600s (90%% of a 3600s token lifetime)", expiry-now)
	}
}

// TestTokenCacheKeyedByDomain verifies two accounts sharing a username that differ
// only by Domain (e.g. a local account and a directory account) do not share cached
// tokens.
func TestTokenCacheKeyedByDomain(t *testing.T) {
	const serverURL = "https://cache-domain-collision.example.com"
	local, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "admin"}})
	if err != nil {
		t.Fatalf("New (local) returned error: %v", err)
	}
	directory, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Domain: "corp.example.com", Username: "admin"}})
	if err != nil {
		t.Fatalf("New (directory) returned error: %v", err)
	}

	if err := local.setCacheAccessToken("token-for-local", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (local) returned error: %v", err)
	}

	if _, ok := directory.getCacheAccessToken(serverURL); ok {
		t.Error("the domain account retrieved a token cached for the local account; Domain is not part of the cache key")
	}

	got, ok := local.getCacheAccessToken(serverURL)
	if !ok || got != "token-for-local" {
		t.Errorf("local account cache = (%q, %v), want (%q, true)", got, ok, "token-for-local")
	}
}

// TestTokenCacheKeyedByDomainAcrossAccounts extends TestTokenCacheKeyedByDomain, which
// seeds only the account with no Domain: seeding the directory account instead exercises
// the other key, and two distinct directory domains are the collision an organization
// actually has. Empty-vs-set alone can pass on nothing more than the empty string being
// different from a value.
func TestTokenCacheKeyedByDomainAcrossAccounts(t *testing.T) {
	const serverURL = "https://cache-domain-accounts.example.com"
	corp := domainServer(t, serverURL, "corp.example.com", "admin")
	lab := domainServer(t, serverURL, "lab.example.com", "admin")
	local := domainServer(t, serverURL, "", "admin")

	if err := corp.setCacheAccessToken("token-for-corp", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (corp) returned error: %v", err)
	}

	if _, ok := lab.getCacheAccessToken(serverURL); ok {
		t.Error("lab.example.com retrieved a token cached for corp.example.com")
	}
	if _, ok := local.getCacheAccessToken(serverURL); ok {
		t.Error("the account with no Domain retrieved a token cached for corp.example.com")
	}

	got, ok := corp.getCacheAccessToken(serverURL)
	if !ok || got != "token-for-corp" {
		t.Errorf("corp cache = (%q, %v), want (%q, true)", got, ok, "token-for-corp")
	}
}

// TestCacheKeyCannotCollide pins the claim cacheKey makes: its first three parts are
// escaped before being joined with "&", which url.QueryEscape always escapes, and the
// fourth is a hex digest, so no two distinct credentials can produce one key.
// Escaping a URL and a username to build an internal map key reads as redundant, and
// dropping it leaves every other cache test green while letting one account be served the
// token cached for another — the collision the keying exists to prevent. The base-URL and
// domain rows below are chosen to concatenate to one string once the escaping is gone.
func TestCacheKeyCannotCollide(t *testing.T) {
	const serverURL = "https://cache-key.example.com"

	seen := map[string]string{}
	for _, c := range []struct{ desc, baseURL, domain, username, password string }{
		{"plain", serverURL, "", "admin", ""},
		{"separator in the username", serverURL, "", "&admin", ""},
		{"the username's value as a domain", serverURL, "admin", "", ""},
		{"separator in the domain", serverURL, "&admin", "", ""},
		{"a pre-escaped separator in the username", serverURL, "", "%26admin", ""},
		// These two differ only in which part carries the separator, and concatenate
		// to the same string once the escaping is gone.
		{"separator ending the base URL", serverURL + "&corp", "", "admin", ""},
		{"separator ending the domain", serverURL, "corp&", "admin", ""},
		// This one collides with "plain" instead if the key is ever built from fewer
		// than the parts it has: the two differ only by Domain.
		{"domain and username split", serverURL, "corp", "admin", ""},
		{"domain and username joined into the username", serverURL, "", "corp&admin", ""},
		// And these three differ from "plain" only by password, which is the part a
		// cache hit never verifies against the server.
		{"password set", serverURL, "", "admin", "s3cret"},
		{"password rotated", serverURL, "", "admin", "s3cret-rotated"},
		{"separator in the password", serverURL, "", "admin", "&"},
	} {
		s := credentialServer(t, c.baseURL, c.domain, c.username, c.password)
		key := s.cacheKey(c.baseURL)
		if first, collides := seen[key]; collides {
			t.Errorf("%s produces the same cache key as %s", c.desc, first)
			continue
		}
		seen[key] = c.desc
	}
}

// TestCacheKeyDoesNotContainThePassword is the other half of putting the password in the
// key: the key is a map key held for the life of the process, so it must carry a digest
// rather than the credential.
func TestCacheKeyDoesNotContainThePassword(t *testing.T) {
	const serverURL, password = "https://cache-key-digest.example.com", "unmistakable-password-value"
	s := credentialServer(t, serverURL, "corp.example.com", "admin", password)

	if key := s.cacheKey(serverURL); strings.Contains(key, password) {
		t.Error("the cache key contains the password in cleartext")
	}
}

// TestTokenCacheKeyedByPassword is the behavior the key change exists for: a cache hit
// returns before the grant is built, so without the password in the key a Server whose
// password is stale, rotated or wrong is served a token obtained with a different one and
// its own password is never presented to the server.
func TestTokenCacheKeyedByPassword(t *testing.T) {
	const serverURL = "https://cache-password.example.com"
	current := credentialServer(t, serverURL, "", "admin", "current-password")
	stale := credentialServer(t, serverURL, "", "admin", "stale-password")

	if err := current.setCacheAccessToken("token-for-current", 3600, serverURL); err != nil {
		t.Fatalf("setCacheAccessToken (current) returned error: %v", err)
	}

	if _, ok := stale.getCacheAccessToken(serverURL); ok {
		t.Error("a Server with a different password was served the cached token")
	}

	got, ok := current.getCacheAccessToken(serverURL)
	if !ok || got != "token-for-current" {
		t.Errorf("current cache = (%q, %v), want (%q, true)", got, ok, "token-for-current")
	}
}

func domainServer(t *testing.T, serverURL, domain, username string) *Server {
	t.Helper()
	return credentialServer(t, serverURL, domain, username, "")
}

func credentialServer(t *testing.T, serverURL, domain, username, password string) *Server {
	t.Helper()
	s, err := New(Configuration{
		ServerURL:   serverURL,
		Credentials: UserCredential{Domain: domain, Username: username, Password: password},
	})
	if err != nil {
		t.Fatalf("New for domain %q, username %q returned error: %v", domain, username, err)
	}
	return s
}

// TestTokenCacheConcurrentAccessNoRace exercises the shared in-memory cache from
// multiple goroutines; run with -race to confirm the store is synchronized.
func TestTokenCacheConcurrentAccessNoRace(t *testing.T) {
	const serverURL = "https://cache-race.example.com"
	s, err := New(Configuration{ServerURL: serverURL, Credentials: UserCredential{Username: "carol"}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.setCacheAccessToken("tok", 3600, serverURL)
			s.getCacheAccessToken(serverURL)
		}()
	}
	wg.Wait()
}
