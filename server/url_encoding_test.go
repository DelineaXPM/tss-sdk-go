package server

import (
	"net/url"
	"strings"
	"testing"
)

// TestUrlForSearchEncodesSearchText is the Finding 1.2 regression: search terms must be
// URL-encoded so a crafted searchText cannot inject or override query parameters.
func TestUrlForSearchEncodesSearchText(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	const malicious = "foo&paging.take=100000"
	raw := s.urlForSearch("secrets", malicious, "")

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("urlForSearch produced an unparseable URL %q: %v", raw, err)
	}
	q := u.Query()

	if got := q.Get("paging.filter.searchText"); got != malicious {
		t.Errorf("searchText = %q, want %q (it should be a single encoded value)", got, malicious)
	}
	if got := q.Get("paging.take"); got != "30" {
		t.Errorf("paging.take = %q, want \"30\"; the search term overrode a fixed parameter", got)
	}
	if strings.Contains(u.RawQuery, "paging.take=100000") {
		t.Errorf("injected paging.take leaked into the query: %q", u.RawQuery)
	}
}

// TestUrlForSearchWithFieldSetsExactMatch verifies the fielded-search branch still sets
// isExactMatch and encodes the field name.
func TestUrlForSearchWithFieldSetsExactMatch(t *testing.T) {
	s, err := New(Configuration{ServerURL: "https://example.com"})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	u, err := url.Parse(s.urlForSearch("secrets", "term", "machine name"))
	if err != nil {
		t.Fatalf("unparseable URL: %v", err)
	}
	q := u.Query()
	if got := q.Get("paging.filter.searchField"); got != "machine name" {
		t.Errorf("searchField = %q, want %q", got, "machine name")
	}
	if got := q.Get("paging.filter.isExactMatch"); got != "true" {
		t.Errorf("isExactMatch = %q, want \"true\"", got)
	}
}
