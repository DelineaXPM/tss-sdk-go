package server

import (
	"os"
	"strings"
	"sync"
	"testing"
)

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
