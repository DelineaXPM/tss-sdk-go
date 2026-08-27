# The Delinea Secret Server SDK for Go

[![Tests](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml/badge.svg)](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml)

A Golang API and examples for [Delinea](https://delinea.com/)
[Secret Server](https://delinea.com/products/secret-server/).

The v3.1 client requires Go 1.26.6. Its authentication, token caching, TLS,
retry, backend-probing, and Platform vault-routing engine is provided by
`github.com/DelineaXPM/delinea-common/api`; this module retains the established
typed Secret Server models and operations.

## Configure

The API requires a `Configuration` containing either username/password
credentials for Secret Server or Platform, or a Secret Server bearer token. Set
either a `Tenant` for Secret Server Cloud or a complete `ServerURL`:

```golang
type UserCredential struct {
    Domain, Username, Password, Token string
}

type Configuration struct {
    Credentials       UserCredential
    ServerURL         string
    TLD               string
    Tenant            string
    TLSClientConfig   *tls.Config
    CACertPEM         string
    Logger            Logger
    AllowInsecureHTTP bool
    Timeout           time.Duration
    MaxRetries        int
    DisableRetries    bool
    RetryBaseDelay    time.Duration
    AllowedVaultHosts string // comma-separated exact host or host:port values
    MaxResponseBytes  int64
    MaxRequestBytes   int64
    MaxAttachmentDownloads int
    MaxSearchResults  int
}
```

`New` validates and snapshots this configuration without network I/O. The first
operation probes the configured URL when username/password credentials could
refer to either Secret Server or Platform. A supplied bearer token skips probing
and is sent directly to Secret Server, preserving v3.0 behavior. Mutating the
embedded configuration after `New` does not reconfigure the client.
Construct `Server` values with `New`; a manually assembled `Server` has no runtime
client and its network methods return a constructor-required error.

Remote plaintext HTTP URLs are rejected by default. Set `AllowInsecureHTTP` only
for an explicitly accepted non-loopback HTTP deployment; loopback development
servers remain usable without it. For private certificate authorities, prefer
`CACertPEM` so identically configured `Server` instances can safely share token
grants. `TLSClientConfig` remains available for advanced TLS customization but
isolates each `Server` from cross-instance token sharing. The two TLS settings
cannot be combined. `New` copies certificate pools, certificate bytes, and other
mutable standard TLS slices. Callback, private-key, cache, writer, and other
interface-owned state cannot be cloned and must remain safe for concurrent use.

Cloud `Tenant` values must be single DNS labels. `TLD` defaults to `com` and
accepts the supported Delinea regions `com`, `eu`, `com.au`, `com.sg`,
`ca`, `co.uk`, and `ae`. Other deployments must use their complete HTTPS
origin in `ServerURL`. Base URLs cannot contain user information, a query, or a
fragment. Supplied bearer tokens must be at least four bytes and cannot contain
whitespace or control characters.

`Timeout` is a total deadline for each context-free SDK operation and also a
progress limit for response headers and stalled body reads. A `Context` method
uses the caller's context for its total deadline. `MaxRetries` counts retries
after the first GET/HEAD or token-grant attempt; zero selects the engine default
and `DisableRetries` selects one attempt. Mutating requests are never replayed.
`MaxResponseBytes` limits the combined buffered response bodies for one SDK
operation, including automatically downloaded attachments.
`MaxRequestBytes` limits each buffered JSON or attachment request and defaults
to 100 MiB. `MaxSearchResults` defaults to 1,000; searches paginate in batches
of 30 and return an error instead of silently truncating results at that limit.
`MaxAttachmentDownloads` limits those automatic downloads and defaults to 100.

Create and update operations involving attachments use multiple server requests
and are not atomic. If the initial write succeeds but an attachment operation or
final refresh fails, the method returns the partial `*Secret` together with a
`*server.PartialWriteError`. Use its `SecretID` to inspect or clean up the
server-side object when it is positive; it is zero when a malformed create
response did not provide a trustworthy identity. Do not blindly retry a create
after this error.

`UserCredential` deliberately emits redacted password and token values when
marshaled to JSON. JSON output is safe for diagnostics but is not a persistence
or round-trip format. JSON input containing real credentials remains supported.

## Use

Define a `Configuration`, use it to create an instance of `Server` for Secret Server:

```golang
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    // Expecting either the tenant or URL to be set
    Tenant:    os.Getenv("TSS_TENANT"),
    ServerURL: os.Getenv("TSS_SERVER_URL"),
})
if err != nil {
    log.Fatal(err)
}
```

OR

Define a `Configuration`, use it to create an instance of `Server` for Platform:

```golang
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_PLATFORM_USERNAME"),
        Password: os.Getenv("TSS_PLATFORM_PASSWORD"),
    },
    ServerURL: os.Getenv("TSS_PLATFORM_URL"),
})
if err != nil {
    log.Fatal(err)
}
```

Get a secret by its numeric ID:

```golang
s, err := tss.Secret(1)

if err != nil {
    log.Fatal("failure calling server.Secret", err)
}

if _, ok := s.Field("password"); !ok {
    log.Fatal("secret has no password field")
}
```

Every network operation also has a `Context` variant, such as
`SecretContext`, `CreateSecretContext`, and `GeneratePasswordContext`, for
caller-controlled cancellation and deadlines.

Reuse a `Server` when practical. Before permanently discarding an initialized
server, call `CloseIdleConnections` to promptly release connections retained by
its underlying HTTP transport. The server remains usable after that call. If the
process replaced `http.DefaultTransport`, that transport may be shared and the
call closes its shared idle pool.

Get a Secret by Path:

```golang
secretPath := `\Secret-Folder\Secret-Name`
secret, err := tss.SecretByPath(secretPath)
if err != nil {
    log.Fatalf("Failed to retrieve secret by path: %v", err)
}

fmt.Printf("Secret ID: %d\n", secret.ID)
fmt.Printf("Secret Name: %s\n", secret.Name)
```

Create a Secret:

```golang
secretModel := new(Secret)
secretModel.Name = "New Secret"
secretModel.SiteID = 1
secretModel.FolderID = 6
secretModel.SecretTemplateID = 8
secretModel.Fields = make([]SecretField, 1)
secretModel.Fields[0].FieldID = 270
secretModel.Fields[0].ItemValue = somePassword

newSecret, err := tss.CreateSecret(*secretModel)
```

Update the Secret:

```golang
secretModel.ID = newSecret.ID
secretModel.Fields[0].ItemValue = someNewPassword

updatedSecret, err := tss.UpdateSecret(*secretModel)
```

Delete the Secret:

```golang
err := tss.DeleteSecret(newSecret.ID)
```

## Logging

Following Go library conventions, **logging is disabled by default**. The SDK will not produce any log output unless you explicitly configure a logger.

### Enabling Logging

To enable logging using Go's standard logger:

```golang
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    ServerURL: os.Getenv("TSS_SERVER_URL"),
    Logger:    log.Default(), // Enable standard log output
})
```

### Custom Logger

You can provide your own logger by implementing the `Logger` interface:

```golang
type Logger interface {
    Printf(format string, v ...interface{})
    Print(v ...interface{})
    Println(v ...interface{})
}
```

Example with a custom logger implementation:

```golang
type MyCustomLogger struct{}

func (l *MyCustomLogger) Printf(format string, v ...interface{}) {
    // Custom implementation - e.g., write to file, send to logging service, etc.
    fmt.Fprintf(os.Stderr, "[CUSTOM] "+format+"\n", v...)
}

func (l *MyCustomLogger) Print(v ...interface{}) {
    // Custom implementation
    fmt.Fprint(os.Stderr, "[CUSTOM] ")
    fmt.Fprintln(os.Stderr, v...)
}

func (l *MyCustomLogger) Println(v ...interface{}) {
    // Custom implementation
    fmt.Fprint(os.Stderr, "[CUSTOM] ")
    fmt.Fprintln(os.Stderr, v...)
}

// Use the custom logger
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    ServerURL: os.Getenv("TSS_SERVER_URL"),
    Logger:    &MyCustomLogger{},
})
```

## Test

Live tenant tests are disabled unless `TSS_INTEGRATION=1` or the target-specific
`TSS_REQUIRE_SECRET_SERVER=1` / `TSS_REQUIRE_PLATFORM=1` flag is set. This keeps
an ordinary `go test ./...` from creating, updating, or deleting secrets merely
because credentials happen to be present in the environment.

The SDK pins the public immutable `delinea-common` v1.0.0 module without a
`replace` directive or private-module authentication.

Live tenant credentials belong only in a `live-tests` environment restricted to
`main`; the ordinary pull-request workflow is credential-free. The scheduled and
manual live workflow uses strict mode, so missing credentials or fixtures fail
instead of silently removing coverage. Repository administrators must protect
`main`, restrict direct creation and movement of `v*` tags to the release workflow,
and configure the main-only `release` environment and deploy key before enabling
releases. The manually dispatched release workflow requires the requested version
to match the unreleased changelog heading, verifies the public dependency, reruns
the complete offline and live suites, confirms `main` has not moved, then creates
an immutable annotated tag and a source-only GitHub release. Module replacements
are forbidden for releases. See [RELEASING.md](RELEASING.md).

Local tests may populate a `Configuration` from repository-root
`test_config.json` for Secret Server or `test_config_platform.json` for
Platform:

```golang
config := new(Configuration)

if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
    json.Unmarshal(cj, &config)
}

tss, err := New(*config)
if err != nil {
    log.Fatal(err)
}
```

`../test_config.json`:

```json
{
    "credentials": {
        "username": "my_app_user",
        "password": "Passw0rd."
    },
    "serverURL": "https://example.local/SecretServer"
}
```

The necessary configuration may instead come from environment variables. A
target configured by both its JSON file and any of its environment variables is
rejected so a stale local file cannot redirect destructive tests to another
tenant. Both JSON filenames are ignored by Git and must never be committed.

| Env Var Name   | Description                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------|
| TSS_USERNAME   | The user name for the Secret Server                                                                                                   |
| TSS_PASSWORD   | The password for the user of Secret Server                                                                                                           |
| TSS_TENANT     | Name for tenants hosted in the Secret Server Cloud. This is prepended to the *.secretservercloud.com domain to determine the server URL. |
| TSS_SERVER_URL | URL for secret servers not hosted in the cloud, eg: https://delinea.mycompany.com/SecretServer or platform URL                                             |
| TSS_PLATFORM_USERNAME | The OAuth client ID for the Platform service user                              |
| TSS_PLATFORM_PASSWORD | The OAuth client secret for the Platform service user                          |
| TSS_PLATFORM_URL | URL for Platform, eg: https://delinea.secureplatform.io/                                             |

### Test #1 - Read Secret Password
Reads the secret with the ID passed in the `TSS_SECRET_ID` environment variable
and extracts the `password` field from it.

### Test #2 - Perform Secret CRUD
Creates a secret with a fixed password using the values passed in the environment variables
below. It then reads the secret from the server, validates its values, updates it, and deletes
it.

| Env Var Name      | Description                                                                   |
|-------------------|-------------------------------------------------------------------------------|
| TSS_SITE_ID       | The numeric ID of the distributed engine site                                 |
| TSS_FOLDER_ID     | The numeric ID of the folder where the secret will be created                 |
| TSS_TEMPLATE_ID   | The numeric ID of the template that defines the secret's fields               |
| TSS_TEST_PASSWORD | The password to set for testing                                               |

### Test #3 - Perform CRUD for an SSH Key Secret
Creates a secret with generated SSH keys using the values passed in the environment variables
below. It then reads the secret from the server, validates its values, updates it, and deletes it.

| Env Var Name                | Description                                                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| TSS_SITE_ID                 | The numeric ID of the distributed engine site                                                                                     |
| TSS_FOLDER_ID               | The numeric ID of the folder where the secret will be created                                                                     |
| TSS_SSH_KEY_TEMPLATE_ID     | The numeric ID of the template that defines the secret's fields. This template must have extended mappings that support SSH keys. |
| TSS_TEST_PASSWORD           | The password to set for testing                                                                                                   |

### Test #4 - Perform field based search for password secret
Searches for secrets with a field value using the values passed in the environment variables below.

| Env Var Name                | Description                                                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| TSS_SEARCH_FIELD            | The secret field to be searched                                                                                                   |
| TSS_SEARCH_TEXT             | The text to search                                                                                                                |
| TSS_SECRET_ID               | The numeric ID of the fixture that must appear in the search results                                                              |

### Test #5 - Perform search for password secret
Searches for secrets containing text using the values passed in the environment variables below.

| Env Var Name                | Description                                                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| TSS_SEARCH_FIELD            | The fixture field whose exact value is validated after the text search                                                            |
| TSS_SEARCH_TEXT             | The text to search                                                                                                                |
| TSS_SECRET_ID               | The numeric ID of the fixture that must appear in the search results                                                              |

### Test #6 - Password Generation
Retrieves the template indicated in the environment variable below, iterates its fields, and
validates that we can generate a password value for every field that is a password field.

| Env Var Name    | Description                                                                   |
|-----------------|-------------------------------------------------------------------------------|
| TSS_TEMPLATE_ID | The numeric ID of the template that defines the secret's fields               |

### Test #7 - Read Secret By Secret-Path
Reads the secret at `TSS_SECRET_PATH`, requires its ID to equal `TSS_SECRET_ID`,
and extracts its fields.
