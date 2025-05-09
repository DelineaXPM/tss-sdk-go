package server

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestSecret tests Secret. Referred to as "Test #1" in the README.
func TestSecret(t *testing.T) {
	t.Run("SecretServer_TestSecret", func(t *testing.T) {
		tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
		GetSecret(t, tss)
	})

	t.Run("Platform_TestSecret", func(t *testing.T) {
		tss, err := initPlatformServer()
		if err != nil {
			t.Error("configuring the Platform Server:", err)
			return
		}
		GetSecret(t, tss)
	})
}

func GetSecret(t *testing.T, tss *Server) {
	id := initIntegerFromEnv("TSS_SECRET_ID", t)
	if id < 0 {
		return
	}

	s, err := tss.Secret(id)

	if err != nil {
		t.Error("calling server.Secret:", err)
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

// TestSecretCRUD tests the creation, read, update, and delete of a Secret.
// Referred to as "Test #2" in the README.
func TestSecretCRUD(t *testing.T) {
	t.Run("SecretServer_TestSecretCRUD", func(t *testing.T) {
		tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
		SecretCRUD(t, tss)
	})

	t.Run("Platform_TestSecretCRUD", func(t *testing.T) {
		tss, err := initPlatformServer()
		if err != nil {
			t.Error("configuring the Platform Server:", err)
			return
		}
		SecretCRUD(t, tss)
	})
}

func SecretCRUD(t *testing.T, tss *Server) {
	siteId := initIntegerFromEnv("TSS_SITE_ID", t)
	folderId := initIntegerFromEnv("TSS_FOLDER_ID", t)
	templateId := initIntegerFromEnv("TSS_TEMPLATE_ID", t)
	testPassword := os.Getenv("TSS_TEST_PASSWORD")

	if testPassword == "" {
		t.Error("testPassword is blank")
		return
	}

	fieldId := -1
	if siteId < 0 || folderId < 0 || templateId < 0 {
		return
	}

	// Retrieve the template and find the first password field
	refSecretTemplate, err := tss.SecretTemplate(templateId)
	if err != nil {
		t.Error("calling server.SecretTemplate:", err)
		return
	}
	for _, field := range refSecretTemplate.Fields {
		if field.IsPassword {
			fieldId = field.SecretTemplateFieldID
			break
		}
	}
	if fieldId < 0 {
		t.Errorf("Unable to find a password field on the secret template with the given id '%d'", templateId)
		return
	}
	t.Logf("Using field ID '%d' for the password field on the template with ID '%d'", fieldId, templateId)

	// Test creation of a new secret
	refSecret := new(Secret)
	password := testPassword
	refSecret.Name = "Test Secret"
	refSecret.SiteID = siteId
	refSecret.FolderID = folderId
	refSecret.SecretTemplateID = templateId
	refSecret.Fields = make([]SecretField, 1)
	refSecret.Fields[0].FieldID = fieldId
	refSecret.Fields[0].ItemValue = password
	sc, err := tss.CreateSecret(*refSecret)
	if err != nil {
		t.Error("calling server.CreateSecret:", err)
		return
	}
	if sc == nil {
		t.Error("created secret data is nil")
		return
	}
	if !validate("created secret folder id", folderId, sc.FolderID, t) {
		return
	}
	if !validate("created secret template id", templateId, sc.SecretTemplateID, t) {
		return
	}
	if !validate("created secret site id", siteId, sc.SiteID, t) {
		return
	}
	createdPassword, matched := sc.FieldById(fieldId)
	if !matched {
		t.Errorf("created secret does not have a password field with the given field id '%d':", fieldId)
		return
	}
	if !validate("created secret password value", password, createdPassword, t) {
		return
	}

	// Test the read of the new secret
	sr, err := tss.Secret(sc.ID)
	if err != nil {
		t.Error("calling server.Secret:", err)
		return
	}
	if sr == nil {
		t.Error("read secret data is nil")
		return
	}
	if !validate("read secret folder id", folderId, sr.FolderID, t) {
		return
	}
	if !validate("read secret template id", templateId, sr.SecretTemplateID, t) {
		return
	}
	if !validate("read secret site id", siteId, sr.SiteID, t) {
		return
	}
	readPassword, matched := sr.FieldById(fieldId)
	if !matched {
		t.Errorf("read secret does not have a password field with the given field id '%d':", fieldId)
		return
	}
	if !validate("read secret password value", password, readPassword, t) {
		return
	}

	// Test the update of the new secret
	newPassword := password + "updated"
	refSecret.ID = sc.ID
	refSecret.Fields[0].ItemValue = newPassword
	su, err := tss.UpdateSecret(*refSecret)
	if err != nil {
		t.Error("calling server.UpdateSecret:", err)
		return
	}
	if su == nil {
		t.Error("updated secret data is nil")
		return
	}
	if !validate("updated secret folder id", folderId, su.FolderID, t) {
		return
	}
	if !validate("updated secret template id", templateId, su.SecretTemplateID, t) {
		return
	}
	if !validate("updated secret site id", siteId, su.SiteID, t) {
		return
	}
	updatedPassword, matched := su.FieldById(fieldId)
	if !matched {
		t.Errorf("updated secret does not have a password field with the given field id '%d':", fieldId)
		return
	}
	if !validate("updated secret password value", newPassword, updatedPassword, t) {
		return
	}

	// Test the deletion of the new secret
	err = tss.DeleteSecret(sc.ID)
	if err != nil {
		t.Error("calling server.DeleteSecret:", err)
		return
	}

	// Test read of the deleted secret fails
	s, err := tss.Secret(sc.ID)
	if s != nil && s.Active {
		t.Errorf("deleted secret with id '%d' returned from read", sc.ID)
	}
}

// TestSecretCRUDForSSHTemplate tests the creation, read, update, and delete
// of a Secret which uses an SSH key template, that is, a template with extended
// mappings that support SSH keys. Referred to as "Test #3" in the README.
func TestSecretCRUDForSSHTemplate(t *testing.T) {
	t.Run("SecretServer_TestSecretCRUDForSSHTemplate", func(t *testing.T) {
		tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
		SecretCRUDForSSHTemplate(t, tss)
	})

	t.Run("Platform_TestSecretCRUDForSSHTemplate", func(t *testing.T) {
		tss, err := initPlatformServer()
		if err != nil {
			t.Error("configuring the Platform Server:", err)
			return
		}
		SecretCRUDForSSHTemplate(t, tss)
	})
}

func SecretCRUDForSSHTemplate(t *testing.T, tss *Server) {
	siteId := initIntegerFromEnv("TSS_SITE_ID", t)
	folderId := initIntegerFromEnv("TSS_FOLDER_ID", t)
	templateId := initIntegerFromEnv("TSS_SSH_KEY_TEMPLATE_ID", t)
	testPassword := os.Getenv("TSS_TEST_PASSWORD")
	if siteId < 0 || folderId < 0 || templateId < 0 {
		return
	}
	if testPassword == "" {
		t.Error("testPassword is blank")
		return
	}

	// Initialize a new secret
	refSecret := new(Secret)
	userName := "SomeUser"
	password := testPassword
	machine := "SomeMachine"
	refSecret.Name = "Test SSH Key Secret"
	refSecret.SiteID = siteId
	refSecret.FolderID = folderId
	refSecret.SecretTemplateID = templateId
	refSecret.SshKeyArgs = &SshKeyArgs{}
	refSecret.SshKeyArgs.GenerateSshKeys = true
	refSecret.SshKeyArgs.GeneratePassphrase = true
	refSecret.Fields = make([]SecretField, 7)

	// Make a best-effort attempt to find the fields related to SSH key generation
	refSecretTemplate, err := tss.SecretTemplate(templateId)
	if err != nil {
		t.Error("calling server.SecretTemplate:", err)
		return
	}
	publicKeyFieldId, publicKeyIdx, privateKeyFieldId, passphraseFieldId := -1, -1, -1, -1
	userNameFieldId, passwordFieldId, machineNameFieldId := -1, -1, -1
	publicRegex := regexp.MustCompile("(?i)public")
	privateRegex := regexp.MustCompile("(?i)private")
	passphraseRegex := regexp.MustCompile("(?i)passphrase")
	userNameRegex := regexp.MustCompile("(?i)username")
	passwordRegex := regexp.MustCompile("(?i)password")
	machineRegex := regexp.MustCompile("(?i)machine")
	hostRegex := regexp.MustCompile("(?i)host")
	idx := 0
	for _, field := range refSecretTemplate.Fields {
		if field.IsFile {
			if publicRegex.MatchString(field.FieldSlugName) {
				publicKeyFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = publicKeyFieldId
				refSecret.Fields[idx].Filename = "" // Let the server generate the name
				publicKeyIdx = idx
				t.Logf("Found a public key field with ID '%d'", publicKeyFieldId)
				idx++
			} else if privateRegex.MatchString(field.FieldSlugName) {
				privateKeyFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = privateKeyFieldId
				refSecret.Fields[idx].Filename = "My Private Key.pem"
				t.Logf("Found a private key field with ID '%d'", privateKeyFieldId)
				idx++
			}
		} else if field.IsPassword {
			if passphraseRegex.MatchString(field.FieldSlugName) {
				passphraseFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = passphraseFieldId
				refSecret.Fields[idx].ItemValue = "" // Let the server generate the value
				t.Logf("Found a passphrase field with ID '%d'", passphraseFieldId)
				idx++
			} else if passwordRegex.MatchString(field.FieldSlugName) {
				passwordFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = passwordFieldId
				refSecret.Fields[idx].ItemValue = password
				t.Logf("Found a password field with ID '%d'", passwordFieldId)
				idx++
			}
		} else {
			if userNameRegex.MatchString(field.FieldSlugName) {
				userNameFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = userNameFieldId
				refSecret.Fields[idx].ItemValue = userName
				t.Logf("Found a username field with ID '%d'", userNameFieldId)
				idx++
			} else if machineRegex.MatchString(field.FieldSlugName) || hostRegex.MatchString(field.FieldSlugName) {
				machineNameFieldId = field.SecretTemplateFieldID
				refSecret.Fields[idx].FieldID = machineNameFieldId
				refSecret.Fields[idx].ItemValue = machine
				t.Logf("Found a machine name field with ID '%d'", machineNameFieldId)
				idx++
			}
		}
	}
	refSecret.Fields = refSecret.Fields[0:idx]

	// Test creation of a new secret
	sc, err := tss.CreateSecret(*refSecret)
	if err != nil {
		t.Error("calling server.CreateSecret:", err)
		return
	}
	if sc == nil {
		t.Error("created secret data is nil")
		return
	}
	if !validate("created secret name", "Test SSH Key Secret", sc.Name, t) {
		return
	}
	if !validate("created secret folder id", folderId, sc.FolderID, t) {
		return
	}
	if !validate("created secret template id", templateId, sc.SecretTemplateID, t) {
		return
	}
	if !validate("created secret site id", siteId, sc.SiteID, t) {
		return
	}
	if publicKeyField, problem := getField(sc, publicKeyFieldId, t); publicKeyField != nil && !problem {
		if !validate("created secret public key field is a file field", true, publicKeyField.IsFile, t) {
			return
		}
		if !validate("created secret public key field has a generated value", true, len(publicKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("created secret public key field has a generated file name", publicKeyField.FieldName, publicKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if privateKeyField, problem := getField(sc, privateKeyFieldId, t); privateKeyField != nil && !problem {
		if !validate("created secret private key field is a file field", true, privateKeyField.IsFile, t) {
			return
		}
		if !validate("created secret private key field has a generated value", true, len(privateKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("created secret private key field has the given file name", "My Private Key.pem", privateKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if passphraseField, problem := getField(sc, passphraseFieldId, t); passphraseField != nil && !problem {
		if !validate("created secret passphrase field is a password field", true, passphraseField.IsPassword, t) {
			return
		}
		if !validate("created secret passphrase field has a value", true, len(passphraseField.ItemValue) > 10, t) {
			return
		}
	} else if problem {
		return
	}
	if userNameField, problem := getField(sc, userNameFieldId, t); userNameField != nil && !problem {
		if !validate("created secret username field has the given value", userName, userNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if passwordField, problem := getField(sc, passwordFieldId, t); passwordField != nil && !problem {
		if !validate("created secret password field is a password field", true, passwordField.IsPassword, t) {
			return
		}
		if !validate("created secret password field has the given value", password, passwordField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if machineNameField, problem := getField(sc, machineNameFieldId, t); machineNameField != nil && !problem {
		if !validate("created secret machine name field has a value", machine, machineNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}

	// Test the read of the new secret
	sr, err := tss.Secret(sc.ID)
	if err != nil {
		t.Error("calling server.Secret:", err)
		return
	}
	if sr == nil {
		t.Error("read secret data is nil")
		return
	}
	if !validate("read secret name", "Test SSH Key Secret", sr.Name, t) {
		return
	}
	if !validate("read secret folder id", folderId, sr.FolderID, t) {
		return
	}
	if !validate("read secret template id", templateId, sr.SecretTemplateID, t) {
		return
	}
	if !validate("read secret site id", siteId, sr.SiteID, t) {
		return
	}
	if publicKeyField, problem := getField(sc, publicKeyFieldId, t); publicKeyField != nil && !problem {
		if !validate("read secret public key field is a file field", true, publicKeyField.IsFile, t) {
			return
		}
		if !validate("read secret public key field has a generated value", true, len(publicKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("read secret public key field has a generated file name", publicKeyField.FieldName, publicKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if privateKeyField, problem := getField(sc, privateKeyFieldId, t); privateKeyField != nil && !problem {
		if !validate("read secret private key field is a file field", true, privateKeyField.IsFile, t) {
			return
		}
		if !validate("read secret private key field has a generated value", true, len(privateKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("read secret private key field has the given file name", "My Private Key.pem", privateKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if passphraseField, problem := getField(sc, passphraseFieldId, t); passphraseField != nil && !problem {
		if !validate("read secret passphrase field is a password field", true, passphraseField.IsPassword, t) {
			return
		}
		if !validate("read secret passphrase field has a value", true, len(passphraseField.ItemValue) > 10, t) {
			return
		}
	} else if problem {
		return
	}
	if userNameField, problem := getField(sc, userNameFieldId, t); userNameField != nil && !problem {
		if !validate("read secret username field has the given value", userName, userNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if passwordField, problem := getField(sc, passwordFieldId, t); passwordField != nil && !problem {
		if !validate("read secret password field is a password field", true, passwordField.IsPassword, t) {
			return
		}
		if !validate("read secret password field has the given value", password, passwordField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if machineNameField, problem := getField(sc, machineNameFieldId, t); machineNameField != nil && !problem {
		if !validate("read secret machine name field has a value", machine, machineNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}

	// Test the update of the new secret
	sc.Name = sc.Name + " (Updated)"
	sc.SshKeyArgs = nil
	if publicKeyIdx > 0 {
		sc.Fields[publicKeyIdx].Filename = "New Filename.txt"
	}
	su, err := tss.UpdateSecret(*sc)
	if err != nil {
		t.Error("calling server.UpdateSecret:", err)
		return
	}
	if su == nil {
		t.Error("updated secret data is nil")
		return
	}
	if !validate("updated secret name", "Test SSH Key Secret (Updated)", su.Name, t) {
		return
	}
	if !validate("updated secret folder id", folderId, su.FolderID, t) {
		return
	}
	if !validate("updated secret template id", templateId, su.SecretTemplateID, t) {
		return
	}
	if !validate("updated secret site id", siteId, su.SiteID, t) {
		return
	}
	if publicKeyField, problem := getField(sc, publicKeyFieldId, t); publicKeyField != nil && !problem {
		if !validate("updated secret public key field is a file field", true, publicKeyField.IsFile, t) {
			return
		}
		if !validate("updated secret public key field has a generated value", true, len(publicKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("updated secret public key field has a generated file name", "New Filename.txt", publicKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if privateKeyField, problem := getField(sc, privateKeyFieldId, t); privateKeyField != nil && !problem {
		if !validate("updated secret private key field is a file field", true, privateKeyField.IsFile, t) {
			return
		}
		if !validate("updated secret private key field has a generated value", true, len(privateKeyField.ItemValue) > 100, t) {
			return
		}
		if !validate("updated secret private key field has the given file name", "My Private Key.pem", privateKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if passphraseField, problem := getField(sc, passphraseFieldId, t); passphraseField != nil && !problem {
		if !validate("updated secret passphrase field is a password field", true, passphraseField.IsPassword, t) {
			return
		}
		if !validate("updated secret passphrase field has a value", true, len(passphraseField.ItemValue) > 10, t) {
			return
		}
	} else if problem {
		return
	}
	if userNameField, problem := getField(sc, userNameFieldId, t); userNameField != nil && !problem {
		if !validate("updated secret username field has the given value", userName, userNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if passwordField, problem := getField(sc, passwordFieldId, t); passwordField != nil && !problem {
		if !validate("updated secret password field is a password field", true, passwordField.IsPassword, t) {
			return
		}
		if !validate("updated secret password field has the given value", password, passwordField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if machineNameField, problem := getField(sc, machineNameFieldId, t); machineNameField != nil && !problem {
		if !validate("updated secret machine name field has a value", machine, machineNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}

	// Test the deletion of the new secret
	err = tss.DeleteSecret(sc.ID)
	if err != nil {
		t.Error("calling server.DeleteSecret:", err)
		return
	}

	// Test read of the deleted secret fails
	s, err := tss.Secret(sc.ID)
	if s != nil && s.Active {
		t.Errorf("deleted secret with id '%d' returned from read", sc.ID)
	}
}

// TestSearch tests Secret. Referred to as "Test #4" in the README.
func TestSearch(t *testing.T) {
	t.Run("SecretServer_TestSearch", func(t *testing.T) {
		tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
		Search(t, tss)
	})

	t.Run("Platform_TestSearch", func(t *testing.T) {
		tss, err := initPlatformServer()
		if err != nil {
			t.Error("configuring the Platform Server:", err)
			return
		}
		Search(t, tss)
	})
}

func Search(t *testing.T, tss *Server) {

	s, err := tss.Secrets(os.Getenv("TSS_SEARCH_TEXT"), os.Getenv("TSS_SEARCH_FIELD"))

	if err != nil {
		t.Error("calling server.Secret:", err)
		return
	}

	if s == nil {
		t.Error("secret data is nil")
	}

	if _, ok := s[0].Field("password"); !ok {
		t.Error("no password field")
	}
}

// TestSearchWithoutField tests Secret. Referred to as "Test #5" in the README.
func TestSearchWithoutField(t *testing.T) {
	t.Run("SecretServer_TestSearchWithoutField", func(t *testing.T) {
		tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
		SearchWithoutField(t, tss)
	})

	t.Run("Platform_TestSearchWithoutField", func(t *testing.T) {
		tss, err := initPlatformServer()
		if err != nil {
			t.Error("configuring the Platform Server:", err)
			return
		}
		SearchWithoutField(t, tss)
	})
}

func SearchWithoutField(t *testing.T, tss *Server) {

	s, err := tss.Secrets(os.Getenv("TSS_SEARCH_TEXT"), "")

	if err != nil {
		t.Error("calling server.Secret:", err)
		return
	}

	if s == nil {
		t.Error("secret data is nil")
	}

	if _, ok := s[0].Field("password"); !ok {
		t.Error("no password field")
	}
}

// TestSecretByPath tests Secret. Referred to as "Test #7" in the README.
func TestSecretByPath(t *testing.T) {
	tss, err := initServer()
		if err != nil {
			t.Error("configuring the Server:", err)
			return
		}
	
	secretPath := initStringFromEnv("TSS_SECRET_PATH", t)
	
	secret, err := tss.SecretByPath(secretPath)
	if err != nil {
	t.Error("Error retrieving secret by path: %v", err)
	}
	
	if secret == nil {
	t.Error("Expected a secret, got nil")
	}
	
	if secret.Name == "" {
	t.Error("Secret name is empty")
	}
	
	if secret.ID == 0 {
	t.Error("Secret ID is zero")
	}
	
	if len(secret.Fields) == 0 {
	t.Error("Secret fields are empty")
	}
}

func initServer() (*Server, error) {
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
			// Expecting either the tenant or URL to be set
			Tenant:    os.Getenv("TSS_TENANT"),
			ServerURL: os.Getenv("TSS_SERVER_URL"),
		}
	}
	return New(*config)
}

func initPlatformServer() (*Server, error) {
	var config *Configuration

	if cj, err := ioutil.ReadFile("../test_config.json"); err == nil {
		config = new(Configuration)

		json.Unmarshal(cj, &config)
	} else {
		config = &Configuration{
			Credentials: UserCredential{
				Username: os.Getenv("TSS_PLATFORM_USERNAME"),
				Password: os.Getenv("TSS_PLATFORM_PASSWORD"),
			},
			ServerURL: os.Getenv("TSS_PLATFORM_URL"),
		}
	}
	return New(*config)
}

// initIntegerFromEnv reads the given environment variable and if it's declared, parses it to an integer. Otherwise,
// returns a default integer of '1'.
func initIntegerFromEnv(envVarName string, t *testing.T) int {
	intValue := 1
	valueFromEnv := os.Getenv(envVarName)
	if valueFromEnv != "" {
		var err error
		intValue, err = strconv.Atoi(valueFromEnv)
		if err != nil {
			t.Errorf("%s must be an integer: %s", envVarName, err)
			return -1
		}
	}
	return intValue
}

// initStringFromEnv reads a string value from the given environment variable.
// It fails the test if the variable is not set, ensuring the required configuration is present.
func initStringFromEnv(envVarName string, t *testing.T) string {
	value := os.Getenv(envVarName)
	if value == "" {
		t.Errorf("%s must be set", envVarName)
	}
	return value
}

func validate(label string, expected interface{}, found interface{}, t *testing.T) bool {
	if expected != found {
		t.Errorf("expecting '%s' to be '%q', but found '%q' instead.", label, expected, found)
		return false
	}
	return true
}

func getField(secret *Secret, fieldId int, t *testing.T) (*SecretField, bool) {
	if fieldId > 0 {
		for _, field := range secret.Fields {
			if field.FieldID == fieldId {
				return &field, false
			}
		}
		t.Errorf("the field id '%d' was found in the SSH template id '%d', but it was not found in the "+
			"secret named '%s'", fieldId, secret.SecretTemplateID, secret.Name)
		return nil, true
	}
	return nil, false
}
