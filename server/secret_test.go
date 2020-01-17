package server

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

// TestSecret tests Secret
func TestSecret(t *testing.T) {
	config := new(Configuration)

	if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
		json.Unmarshal(cj, &config)
	}

	tss, err := New(*config)

	if err != nil {
		t.Error("configuring the Server:", err)
		return
	}

	s, err := tss.Secret(1)

	if err != nil {
		t.Error("calling secrets.Secret:", err)
		return
	}

	if s == nil {
		t.Error("secret data is nil")
	}

	if _, ok := s.Field("password"); !ok {
		t.Error("no password field")
	}

	if _, ok := s.Field("nonexistent"); ok {
		t.Error("s.Field says nonexistent field exists")
	}
}
