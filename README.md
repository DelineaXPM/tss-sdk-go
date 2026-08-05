# The Delinea Secret Server SDK for Go

[![Tests](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml/badge.svg)](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml)

A Golang API and examples for [Delinea](https://delinea.com/)
[Secret Server](https://delinea.com/products/secret-server/).

## Configure

The API requires a `server.Configuration` containing credentials and exactly one of
`Tenant` (Secret Server Cloud) or `ServerURL` (Secret Server or Platform):

```golang
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    Tenant: os.Getenv("TSS_TENANT"),
})
if err != nil {
    log.Fatal(err)
}
```

### TLS configuration

A `TLSClientConfig` is applied only to the HTTP client used by the `Server` it is
configured on. It does **not** modify `http.DefaultTransport` or affect any other HTTPS
traffic in your process, so a custom `RootCAs` pool for Secret Server never changes
certificate verification elsewhere. The TLS configuration is cloned; changing it after
`New` returns does not mutate the running client.

`HTTPClient` can supply a proxying, tracing, or policy transport. The SDK preserves that
client's transport, cookie jar, and redirect policy in a scoped copy. If both
`HTTPClient` and `TLSClientConfig` are set, the transport must be an `*http.Transport`
so the TLS policy can be cloned safely; `New` otherwise returns an error instead of
silently bypassing either policy.

Redirects are restricted to the original origin. Token endpoints do not follow redirects,
preventing passwords and client secrets from being replayed to a redirect target.

### Request timeout

Every request has a 60-second timeout by default. Set `Timeout` to choose another bound,
or set `DisableTimeout` only when every call uses a context deadline. Public operations
have context variants such as `SecretContext`, `SecretsContext`, and
`CreateSecretContext`.

Safe reads (`GET` and `HEAD`) retry transient network errors, HTTP 429, and HTTP 5xx up
to two times with exponential jitter. Writes, deletes, generated-password requests, and
uploads are never retried. `MaxRetries`, `RetryBaseDelay`, and `DisableRetries` customize
that behavior.

### Platform vault trust

Platform discovery accepts only HTTPS vault URLs. Same-origin vaults and Delinea Secret
Server Cloud domains are trusted by default. For an on-premises Platform that returns a
vault on another host, add that exact hostname (or `host:port`) to `AllowedVaultHosts`,
or provide a `VaultURLValidator`. Plaintext URLs, user information, query strings, and
fragments are always rejected.

### Response size cap

The SDK reads at most 100 MiB of an API response body, well above Secret Server's default
10 MB file-attachment limit and Delinea's recommended maximum of 30 MB. If your
on-premises Secret Server is configured to allow larger attachments, set
`MaxResponseBytes` to a matching value. An oversized response returns an error.

### Credential redaction

Formatting a `Server`, `Configuration`, or `UserCredential` with the `fmt` verbs (`%v`,
`%+v`, `%s`, `%#v`) prints `<redacted>` in place of `Password` and `Token`.
`encoding/json` also emits redaction markers while JSON configuration files still
decode normally. Other serializers and reflection can still inspect exported fields;
do not send a live `Configuration` to telemetry or a generic serializer.

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
secret, err := tss.Secret(1)

if err != nil {
    log.Fatal("failure calling server.Secret: ", err)
}

if _, ok := secret.Field("password"); !ok {
    log.Fatal("secret has no password field")
}
fmt.Printf("retrieved secret %d (%s)\n", secret.ID, secret.Name)
```

Long-running callers should pass their own operation deadline. The context covers
health detection, authentication, retry backoff, the API request, and attachment reads:

```golang
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

secret, err := tss.SecretContext(ctx, 1)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("retrieved secret %d (%s)\n", secret.ID, secret.Name)
```

Non-2xx responses return `*server.HTTPError`, whose `StatusCode` can be inspected
without parsing its message:

```golang
var httpErr *server.HTTPError
if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusTooManyRequests {
    // Apply the application's rate-limit policy.
}
```

Get a Secret by Path:

```golang
secretPath := "/Secret-Folder/Secret-Name"
secret, err := tss.SecretByPath(secretPath)
if err != nil {
    log.Fatalf("Failed to retrieve secret by path: %v", err)
}

fmt.Printf("Secret ID: %d\n", secret.ID)
fmt.Printf("Secret Name: %s\n", secret.Name)
```

Create a Secret:

```golang
secretModel := new(server.Secret)
secretModel.Name = "New Secret"
secretModel.SiteID = 1
secretModel.FolderID = 6
secretModel.SecretTemplateID = 8
secretModel.Fields = make([]server.SecretField, 1)
secretModel.Fields[0].FieldID = 270
secretModel.Fields[0].ItemValue = somePassword

newSecret, err := tss.CreateSecret(*secretModel)
if err != nil {
    log.Fatal(err)
}
```

Update the Secret:

```golang
secretModel.ID = newSecret.ID
secretModel.Fields[0].ItemValue = someNewPassword

updatedSecret, err := tss.UpdateSecret(*secretModel)
if err != nil {
    log.Fatal(err)
}
```

Delete the Secret:

```golang
err := tss.DeleteSecret(updatedSecret.ID)
if err != nil {
    log.Fatal(err)
}
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

Unit tests need no configuration and no network:

```sh
go test ./...
```

The tests that exercise a real server form a battery: each case runs against every
configured target as a subtest named for that target, so the battery is selectable per
target.

```sh
go test ./server -run '/SecretServer'   # whole battery against Secret Server
go test ./server -run '/Platform'       # whole battery against Platform
go test ./server -run 'TestSecretCRUD'  # one case against every configured target
go test ./server -v                     # everything available, naming what ran and what was skipped
```

A target runs when it is configured and is skipped otherwise, so `go test ./...`
passes on a clean checkout. A target counts as configured when its config file is
present or any of its environment variables is set — "any", not "all", so a partly
configured target fails loudly instead of quietly skipping. Set
`TSS_REQUIRE_SECRET_SERVER=1` or `TSS_REQUIRE_PLATFORM=1` to make one target and all of
its case fixtures mandatory. `TSS_INTEGRATION=1` is shorthand for requiring both. CI
sets the per-target flag when that target's primary credential is available, so one
target cannot hide missing coverage for the other.

Secret Server reads `../test_config.json` and the `TSS_*` variables; Platform reads
`../test_config_platform.json` and the `TSS_PLATFORM_*` variables. The two files are
separate so that the Platform subtests cannot silently run against a Secret Server.

Cases that address a specific secret, folder, template, or search term are skipped
unless the matching variable is set. In required mode those missing or unsuitable
fixtures fail instead, rather than leaving a green run with silent gaps.

The tests populate a `Configuration` from JSON:

```golang
var config server.Configuration
cj, err := ioutil.ReadFile("../test_config.json")
if err != nil {
    log.Fatal(err)
}
if err := json.Unmarshal(cj, &config); err != nil {
    log.Fatal(err)
}

tss, err := server.New(config)
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

The necessary configuration may also be configured from environment variables:

| Env Var Name   | Description                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------|
| TSS_USERNAME   | The user name for the Secret Server                                                                                                   |
| TSS_PASSWORD   | The password for the user of Secret Server                                                                                                           |
| TSS_TENANT     | Name for tenants hosted in the Secret Server Cloud. This is prepended to the *.secretservercloud.com domain to determine the server URL. |
| TSS_SERVER_URL | URL for secret servers not hosted in the cloud, eg: https://delinea.mycompany.com/SecretServer or platform URL                                             |
| TSS_PLATFORM_USERNAME | The user name for the Platform user                                             |
| TSS_PLATFORM_PASSWORD | The password for the Platform user                                             |
| TSS_PLATFORM_URL | URL for Platform, eg: https://delinea.secureplatform.com/                                            |
| TSS_PLATFORM_ALLOWED_VAULT_HOSTS | Comma-separated cross-origin vault hosts explicitly trusted for an on-premises Platform |

### Test #1 - Read Secret Password
Reads the secret with ID `1` or the ID passed in the `TSS_SECRET_ID` environment variable
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

### Test #5 - Perform search for password secret
Searches for secrets containing text using the values passed in the environment variables below.

| Env Var Name                | Description                                                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| TSS_SEARCH_TEXT             | The text to search                                                                                                                |

### Test #6 - Password Generation
Retrieves the template indicated in the environment variable below, iterates its fields, and
validates that we can generate a password value for every field that is a password field.

| Env Var Name    | Description                                                                   |
|-----------------|-------------------------------------------------------------------------------|
| TSS_TEMPLATE_ID | The numeric ID of the template that defines the secret's fields               |

### Test #7 - Read Secret By Secret-Path
Reads the secret with Secret-Path passed in the `TSS_SECRET_PATH` environment variable
and extracts the Secret fields from it.
