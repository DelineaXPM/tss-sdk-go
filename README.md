# The Thycotic Secret Server SDK for Go

![Tests](https://github.com/thycotic/tss-sdk-go/workflows/Tests/badge.svg)

A Golang API and examples for [Thycotic](https://thycotic.com/)
[Secret Server](https://thycotic.com/products/secret-server/).

## Configure

The API requires a `Configuration` object containing a `Username`, `Password`
and either a `Tenant` for Secret Server Cloud or a `ServerURL`:

```golang
type UserCredential struct {
    Username, Password string
}

type Configuration struct {
    Credentials UserCredential
    ServerURL, TLD, Tenant, apiPathURI, tokenPathURI string
}
```

The unit tests populate `Configuration` from JSON:

```golang
config := new(Configuration)

if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
    json.Unmarshal(cj, &config)
}

tss := New(*config)
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

## Test

The unit test tries to read the secret with ID `1` and extract the `password`
field from it.

## Use

Define a `Configuration`, use it to create an instance of `Server` and get a `Secret`:

```golang
tss := server.New(server.Configuration{
    Username: os.Getenv("TSS_API_USERNAME"),
    Password: os.Getenv("TSS_API_PASSWORD"),
    Tenant:   os.Getenv("TSS_API_TENANT"),
})
s, err := tss.Secret(1)

if err != nil {
    log.Fatal("failure calling server.Secret", err)
}

if pw, ok := secret.Field("password"); ok {
    fmt.Print("the password is", pw)
}
```
