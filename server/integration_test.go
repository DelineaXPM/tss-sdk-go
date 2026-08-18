package server

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

const integrationOptIn = "TSS_INTEGRATION"

type integrationTarget struct {
	name       string
	envPrefix  string
	requireVar string
	configFile string
	envVars    []string
	envConfig  func() Configuration
}

func integrationTargets() []integrationTarget {
	return []integrationTarget{
		{
			name:       "SecretServer",
			requireVar: "TSS_REQUIRE_SECRET_SERVER",
			configFile: "../test_config.json",
			envVars:    []string{"TSS_USERNAME", "TSS_PASSWORD", "TSS_TENANT", "TSS_SERVER_URL"},
			envConfig: func() Configuration {
				return Configuration{
					Credentials: UserCredential{Username: os.Getenv("TSS_USERNAME"), Password: os.Getenv("TSS_PASSWORD")},
					Tenant:      os.Getenv("TSS_TENANT"), ServerURL: os.Getenv("TSS_SERVER_URL"),
				}
			},
		},
		{
			name:       "Platform",
			envPrefix:  "TSS_PLATFORM_",
			requireVar: "TSS_REQUIRE_PLATFORM",
			configFile: "../test_config_platform.json",
			envVars:    []string{"TSS_PLATFORM_USERNAME", "TSS_PLATFORM_PASSWORD", "TSS_PLATFORM_URL"},
			envConfig: func() Configuration {
				return Configuration{
					Credentials:       UserCredential{Username: os.Getenv("TSS_PLATFORM_USERNAME"), Password: os.Getenv("TSS_PLATFORM_PASSWORD")},
					ServerURL:         os.Getenv("TSS_PLATFORM_URL"),
					AllowedVaultHosts: os.Getenv("TSS_PLATFORM_ALLOWED_VAULT_HOSTS"),
				}
			},
		},
	}
}

func (target integrationTarget) configured() bool {
	if _, err := os.Stat(target.configFile); err == nil {
		return true
	}
	for _, name := range target.envVars {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

func (target integrationTarget) required() bool {
	return os.Getenv(integrationOptIn) != "" || os.Getenv(target.requireVar) != ""
}

func (target integrationTarget) server(t *testing.T) *Server {
	t.Helper()
	config := target.envConfig()
	if data, err := os.ReadFile(target.configFile); err == nil {
		config = Configuration{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("parsing %s: %v", target.configFile, err)
		}
	}
	server, err := New(config)
	if err != nil {
		t.Fatalf("configuring %s: %v", target.name, err)
	}
	return server
}

func runBattery(t *testing.T, body func(*testing.T, *Server)) {
	for _, target := range integrationTargets() {
		t.Run(target.name, func(t *testing.T) {
			if !target.configured() {
				if target.required() {
					t.Fatalf("%s integration is required but not configured", target.name)
				}
				t.Skipf("%s integration is not configured", target.name)
			}
			body(t, target.server(t))
		})
	}
}

func fixtureNames(t *testing.T, name string) []string {
	t.Helper()
	for _, target := range integrationTargets() {
		if target.envPrefix != "" && strings.HasSuffix(t.Name(), "/"+target.name) {
			return []string{strings.Replace(name, "TSS_", target.envPrefix, 1)}
		}
	}
	return []string{name}
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	names := fixtureNames(t, name)
	for _, candidate := range names {
		if value := os.Getenv(candidate); value != "" {
			return value
		}
	}
	if integrationRequired(t) {
		t.Fatalf("one of %s must be set", strings.Join(names, " / "))
	}
	t.Skipf("set %s to run this case", strings.Join(names, " or "))
	return ""
}

func requireIntEnv(t *testing.T, name string) int {
	t.Helper()
	value, err := strconv.Atoi(requireEnv(t, name))
	if err != nil {
		t.Fatalf("%s must be an integer: %v", name, err)
	}
	return value
}

func integrationRequired(t *testing.T) bool {
	for _, target := range integrationTargets() {
		if strings.HasSuffix(t.Name(), "/"+target.name) {
			return target.required()
		}
	}
	return os.Getenv(integrationOptIn) != ""
}

func deleteAfterTest(t *testing.T, server *Server, secretID int) {
	t.Helper()
	t.Cleanup(func() { _ = server.DeleteSecret(secretID) })
}
