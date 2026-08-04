package server

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The tests that exercise a real server form a battery: each one runs against every
// configured target, as a subtest named for that target. That makes the battery
// selectable per target:
//
//	go test ./server -run '/SecretServer'    # whole battery against Secret Server
//	go test ./server -run '/Platform'        # whole battery against Platform
//	go test ./server -run 'TestSecretCRUD'   # one case against every configured target
//	go test ./server -v -run '/'             # everything available, with names
//
// A target that is not configured is skipped, so `go test ./...` passes on a clean
// clone and on pull requests from forks, where repository secrets are absent.
//
// A target counts as configured when its config file is present or any of its
// environment variables is set. The check is deliberately "any variable set", not "all
// of them": a partly configured target is a misconfiguration, not an invitation to
// skip, so it runs and fails loudly rather than passing green with nothing tested.
// Each target has an independent requirement variable so one configured service does
// not accidentally make the other mandatory. TSS_INTEGRATION remains a convenient
// local shorthand that requires both.
const integrationOptIn = "TSS_INTEGRATION"

// target is one server the battery runs against.
type target struct {
	name string
	// envPrefix replaces the leading "TSS_" of a fixture variable to give this
	// target its own value, empty for the target that uses the unscoped names.
	envPrefix  string
	requireVar string
	configFile string
	envVars    []string
	envConfig  func() Configuration
}

// targets lists the servers the battery runs against. Each reads its own config file,
// so a developer using config files rather than environment variables gets a genuine
// Platform for the Platform subtests instead of a second copy of the Secret Server
// configuration.
func targets() []target {
	return []target{
		{
			name:       "SecretServer",
			requireVar: "TSS_REQUIRE_SECRET_SERVER",
			configFile: "../test_config.json",
			envVars:    []string{"TSS_USERNAME", "TSS_PASSWORD", "TSS_TENANT", "TSS_SERVER_URL"},
			envConfig: func() Configuration {
				return Configuration{
					Credentials: UserCredential{
						Username: os.Getenv("TSS_USERNAME"),
						Password: os.Getenv("TSS_PASSWORD"),
					},
					// Expecting either the tenant or URL to be set
					Tenant:    os.Getenv("TSS_TENANT"),
					ServerURL: os.Getenv("TSS_SERVER_URL"),
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
					Credentials: UserCredential{
						Username: os.Getenv("TSS_PLATFORM_USERNAME"),
						Password: os.Getenv("TSS_PLATFORM_PASSWORD"),
					},
					ServerURL: os.Getenv("TSS_PLATFORM_URL"),
				}
			},
		},
	}
}

func (tgt target) configured() bool {
	if _, err := os.Stat(tgt.configFile); err == nil {
		return true
	}
	for _, name := range tgt.envVars {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

func (tgt target) required() bool {
	return os.Getenv(integrationOptIn) != "" || os.Getenv(tgt.requireVar) != ""
}

func (tgt target) server(t *testing.T) *Server {
	t.Helper()

	config := tgt.envConfig()
	if cj, err := ioutil.ReadFile(tgt.configFile); err == nil {
		config = Configuration{}
		if err := json.Unmarshal(cj, &config); err != nil {
			t.Fatalf("parsing %s: %v", tgt.configFile, err)
		}
	}

	s, err := New(config)
	if err != nil {
		t.Fatalf("configuring the %s target: %v", tgt.name, err)
	}
	return s
}

// runBattery runs body against every configured target, as a subtest named for the
// target.
func runBattery(t *testing.T, body func(t *testing.T, tss *Server)) {
	for _, tgt := range targets() {
		t.Run(tgt.name, func(t *testing.T) {
			if !tgt.configured() {
				if tgt.required() {
					t.Fatalf("the %s battery is required by %s but is not configured; set %s or provide %s",
						tgt.name, tgt.requireVar, strings.Join(tgt.envVars, " / "), tgt.configFile)
				}
				t.Skipf("skipping the %s battery: set %s, or provide %s, to run it; set %s to require it",
					tgt.name, strings.Join(tgt.envVars, " / "), tgt.configFile, tgt.requireVar)
			}
			body(t, tgt.server(t))
		})
	}
}

// fixtureNames returns the variables to consult for a fixture, most specific first.
// A secret id, path or search term that exists on one target rarely exists on
// another, so each target may override a fixture under its own prefix —
// TSS_SECRET_ID becomes TSS_PLATFORM_SECRET_ID for the Platform target — while the
// unscoped name stays the shared default. The target is read from the subtest name
// that runBattery established.
func fixtureNames(t *testing.T, name string) []string {
	t.Helper()
	for _, tgt := range targets() {
		if tgt.envPrefix != "" && strings.HasSuffix(t.Name(), "/"+tgt.name) {
			return []string{strings.Replace(name, "TSS_", tgt.envPrefix, 1), name}
		}
	}
	return []string{name}
}

// requireEnv returns a fixture the case cannot run without. Guessing a value would run
// the case against whatever happens to occupy that id or path on a real server and
// report the resulting server error as though the SDK were broken.
func requireEnv(t *testing.T, name string) string {
	t.Helper()
	names := fixtureNames(t, name)
	for _, candidate := range names {
		if value := os.Getenv(candidate); value != "" {
			return value
		}
	}
	if integrationRequired(t) {
		t.Fatalf("one of %s must be set for the required integration target", strings.Join(names, " / "))
	}
	t.Skipf("skipping: set %s to run this case", strings.Join(names, " or "))
	return ""
}

func integrationRequired(t *testing.T) bool {
	t.Helper()
	for _, tgt := range targets() {
		if strings.HasSuffix(t.Name(), "/"+tgt.name) {
			return tgt.required()
		}
	}
	return os.Getenv(integrationOptIn) != ""
}

func skipOrFailIntegration(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	if integrationRequired(t) {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func requireIntEnv(t *testing.T, name string) int {
	t.Helper()
	value, err := strconv.Atoi(requireEnv(t, name))
	if err != nil {
		t.Fatalf("%s must be an integer: %v", name, err)
	}
	return value
}

// deleteAfterTest removes a secret the battery created, so a case that fails partway
// does not leave credentials behind on a real server. The battery also deletes
// explicitly where deletion is the behavior under test; this is the safety net, so its
// error is ignored.
func deleteAfterTest(t *testing.T, tss *Server, secretID int) {
	t.Helper()
	t.Cleanup(func() {
		_ = tss.DeleteSecret(secretID)
	})
}
