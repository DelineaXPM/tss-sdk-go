# The Thycotic Secret Server SDK for Go

A Golang API and examples for [Thycotic](https://thycotic.com/)
[Secret Server](https://thycotic.com/products/secret-server/).

## Configure

The API requires a `Configuration` object containing a `Username`, `Password`
and either a `Tenant` for Secret Server Cloud or a `ServerURL`.

For example, the tests populates `Configuration` from JSON:

```golang
config := new(Configuration)

if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
    json.Unmarshal(cj, &config)
}

tss := New(*config)
```

Example JSON configuration:

```json
{
    "username": "my_app_user",
    "password": "Passw0rd.",
    "tenant": "mytenant"
}
```

NOTE: if both `serverURL` and `tenant` are defined, the latter takes precedence.

## Test

The test tries to read the secret with ID `1` from the configured server, and
extract the `password` field from it.

## Use

Define a `Configuration` then use it to create an instance of `Server`:

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
