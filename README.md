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

## Use

Define a `Configuration`, use it to create an instance of `Server`:

```golang
tss := server.New(server.Configuration{
    Credentials: UserCredential{
        Username: os.Getenv("TSS_USERNAME"),
        Password: os.Getenv("TSS_PASSWORD"),
    },
    // Expecting either the tenant or URL to be set
    Tenant:    os.Getenv("TSS_API_TENANT"),
    ServerURL: os.Getenv("TSS_SERVER_URL"),
})
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

## Test

The tests populate a `Configuration` from JSON:

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

The necessary configuration may also be configured from environment variables: 

| Env Var Name   | Description                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------|
| TSS_USERNAME   | The user name for the Secret Server                                                                                                      |
| TSS_PASSWORD   | The password for the user                                                                                                                |
| TSS_TENANT     | Name for tenants hosted in the Secret Server Cloud. This is prepended to the *.secretservercloud.com domain to determine the server URL. |
| TSS_SERVER_URL | URL for servers not hosted in the cloud, eg: https://thycotic.mycompany.com/SecretServer                                                 |

### Test #1
Reads the secret with ID `1` or the ID passed in the `TSS_SECRET_ID` environment variable 
and extracts the `password` field from it.

### Test #2
Creates a secret with a fixed password using the values passed in the environment variables 
below. It then reads the secret from the server, validates its values, updates it, and deletes 
it.

| Env Var Name    | Description                                                                   |
|-----------------|-------------------------------------------------------------------------------|
| TSS_SITE_ID     | The numeric ID of the distributed engine site                                 |
| TSS_FOLDER_ID   | The numeric ID of the folder where the secret will be created                 |
| TSS_TEMPLATE_ID | The numeric ID of the template that defines the secret's fields               |
| TSS_FIELD_ID    | The numeric ID of a field on the template that happens to be a password field |

### Test #3
Creates a secret with a generated password using the values passed in the environment variables 
below. It then deletes the secret.

| Env Var Name    | Description                                                                   |
|-----------------|-------------------------------------------------------------------------------|
| TSS_SITE_ID     | The numeric ID of the distributed engine site                                 |
| TSS_FOLDER_ID   | The numeric ID of the folder where the secret will be created                 |
| TSS_TEMPLATE_ID | The numeric ID of the template that defines the secret's fields               |
| TSS_FIELD_ID    | The numeric ID of a field on the template that happens to be a password field |
