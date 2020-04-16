package server

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
)

// TestSecret tests Secret
func TestSecret(t *testing.T) {
	var config *Configuration

	if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
		config = new(Configuration)

		json.Unmarshal(cj, &config)
	} else {
		config = &Configuration{
			Credentials: UserCredential{
				Username: os.Getenv("TSS_USERNAME"),
				Password: os.Getenv("TSS_PASSWORD"),
			},
			Tenant: os.Getenv("TSS_TENANT"),
		}
	}

	id := 1
	idFromEnv := os.Getenv("TSS_SECRET_ID")

	if idFromEnv != "" {
		var err error

		id, err = strconv.Atoi(idFromEnv)

		if err != nil {
			t.Errorf("TSS_SECRET_ID must be an integer: %s", err)
			return
		}
	}

	tss, err := New(*config)

	if err != nil {
		t.Error("configuring the Server:", err)
		return
	}

	s, err := tss.Secret(id)

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
