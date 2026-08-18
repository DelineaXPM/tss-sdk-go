# The Delinea Secret Server SDK for Go

[![Tests](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml/badge.svg)](https://github.com/DelineaXPM/tss-sdk-go/actions/workflows/tests.yml)

A Golang API and examples for [Delinea](https://delinea.com/)
[Secret Server](https://delinea.com/products/secret-server/).

The v3.1 client requires Go 1.26.6. Its authentication, token caching, TLS,
retry, backend-probing, and Platform vault-routing engine is provided by
`github.com/DelineaXPM/delinea-tools/api`; this module retains the established
typed Secret Server models and operations.

## Configure

The API requires a `Configuration` object containing a `Username`, `Password`
and either a `Tenant` for Secret Server Cloud or a `ServerURL` of Secret Server/Platform:

```golang
type UserCredential struct {
    Username, Password string
}

type Configuration struct {
    Credentials       UserCredential
    ServerURL         string
    TLD               string
    Tenant            string
    TLSClientConfig   *tls.Config
    Logger            Logger
    Timeout           time.Duration
    MaxRetries        int
    DisableRetries    bool
    RetryBaseDelay    time.Duration
    AllowedVaultHosts string // comma-separated exact host or host:port values
    MaxResponseBytes  int64
}
```

`New` validates and snapshots this configuration without network I/O. The first
operation probes the configured URL when username/password credentials could
refer to either Secret Server or Platform. A supplied bearer token skips probing
and is sent directly to Secret Server, preserving v3.0 behavior. Mutating the
embedded configuration after `New` does not reconfigure the client.
Construct `Server` values with `New`; a manually assembled `Server` has no runtime
client and its network methods return a constructor-required error.

`Timeout` is a progress limit for response headers and stalled body reads, not a
total duration for a continuously flowing response. `MaxRetries` counts retries
after the first GET/HEAD or token-grant attempt; zero selects the engine default
and `DisableRetries` selects one attempt. Mutating requests are never replayed.

## Use

Define a `Configuration`, use it to create an instance of `Server` for Secret Server:

```golang
tss, err := server.New(server.Configuration{
    Credentials: server.UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    // Expecting either the tenant or URL to be set
    Tenant:    os.Getenv("TSS_API_TENANT"),
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

if pw, ok := secret.Field("password"); ok {
    fmt.Print("the password is", pw)
}
```

Every network operation also has a `Context` variant, such as
`SecretContext`, `CreateSecretContext`, and `GeneratePasswordContext`, for
caller-controlled cancellation and deadlines.

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

### Private dependency during facade development

Until `delinea-tools` is public at v1.0.0, this branch uses its private v0.1.0
candidate without a `replace` directive. Local development requires GitHub read
access and:

```shell
go env -w GOPRIVATE='github.com/DelineaXPM/*'
go env -w GONOSUMDB='github.com/DelineaXPM/*'
gh auth setup-git
```

CI temporarily requires a read-only `DELINEA_TOOLS_READ_TOKEN` repository
secret. Before releasing tss-sdk-go, update `go.mod` to the public immutable
`delinea-tools` v1.0.0 tag and remove this temporary authentication setup.

The tests populate a `Configuration` from JSON:

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
    "serverURL": "http://example.local/SecretServer"
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
