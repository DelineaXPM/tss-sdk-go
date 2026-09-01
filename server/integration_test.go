package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
			envVars:    []string{"TSS_PLATFORM_USERNAME", "TSS_PLATFORM_PASSWORD", "TSS_PLATFORM_URL", "TSS_PLATFORM_ALLOWED_VAULT_HOSTS"},
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
	return target.environmentConfigured()
}

func (target integrationTarget) environmentConfigured() bool {
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

func (target integrationTarget) configuration() (Configuration, error) {
	config := target.envConfig()
	data, err := os.ReadFile(target.configFile)
	switch {
	case err == nil && target.environmentConfigured():
		return Configuration{}, fmt.Errorf("%s integration is configured by both environment variables and %s; choose one source", target.name, target.configFile)
	case err == nil:
		config = Configuration{}
		if err := json.Unmarshal(data, &config); err != nil {
			return Configuration{}, fmt.Errorf("parsing %s: %w", target.configFile, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return Configuration{}, fmt.Errorf("reading %s: %w", target.configFile, err)
	}
	return config, nil
}

func (target integrationTarget) server(t *testing.T) *Server {
	t.Helper()
	config, err := target.configuration()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(config)
	if err != nil {
		t.Fatalf("configuring %s: %v", target.name, err)
	}
	return server
}

func TestIntegrationConfigurationRejectsAmbiguousSources(t *testing.T) {
	const envName = "TSS_TEST_AMBIGUOUS_CONFIG"
	t.Setenv(envName, "configured")
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, []byte(`{"ServerURL":"https://example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target := integrationTarget{
		name:       "TestTarget",
		configFile: configFile,
		envVars:    []string{envName},
		envConfig:  func() Configuration { return Configuration{} },
	}
	if _, err := target.configuration(); err == nil || !strings.Contains(err.Error(), "both environment variables") {
		t.Fatalf("configuration error = %v, want ambiguous-source error", err)
	}
}

func TestPlatformVaultTrustCountsAsEnvironmentConfiguration(t *testing.T) {
	target := integrationTargets()[1]
	for _, name := range target.envVars {
		t.Setenv(name, "")
	}
	t.Setenv("TSS_PLATFORM_ALLOWED_VAULT_HOSTS", "vault.example")
	if !target.environmentConfigured() {
		t.Fatal("Platform vault trust did not count as environment configuration")
	}
}

func runBattery(t *testing.T, body func(*testing.T, *Server)) {
	for _, target := range integrationTargets() {
		t.Run(target.name, func(t *testing.T) {
			if !target.required() {
				t.Skipf("%s integration requires %s=1 or %s=1", target.name, integrationOptIn, target.requireVar)
			}
			if !target.configured() {
				t.Fatalf("%s integration is required but not configured", target.name)
			}
			body(t, target.server(t))
		})
	}
}

func TestRunBatteryRequiresExplicitOptIn(t *testing.T) {
	t.Setenv(integrationOptIn, "")
	t.Setenv("TSS_REQUIRE_SECRET_SERVER", "")
	t.Setenv("TSS_REQUIRE_PLATFORM", "")
	called := false
	runBattery(t, func(*testing.T, *Server) { called = true })
	if called {
		t.Fatal("ambient integration configuration ran a live test without explicit opt-in")
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

func deleteAfterTest(t *testing.T, server *Server, secretID int) func() {
	t.Helper()
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		if err := server.DeleteSecret(secretID); err != nil {
			t.Errorf("cleaning up test secret %d: %v", secretID, err)
		}
	})
	return func() { deleted = true }
}
