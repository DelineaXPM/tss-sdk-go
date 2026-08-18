package server

import (
	"errors"
	"regexp"
	"testing"
)

// TestSecret tests Secret. Referred to as "Test #1" in the README.
func TestSecret(t *testing.T) {
	runBattery(t, GetSecret)
}

func GetSecret(t *testing.T, tss *Server) {
	id := requireIntEnv(t, "TSS_SECRET_ID")
	s, err := tss.Secret(id)

	if err != nil {
		t.Fatal("calling server.Secret:", err)
	}

	if s == nil {
		t.Fatal("secret data is nil")
	}

	if _, ok := s.Field("password"); !ok {
		t.Fatal("no password field")
	}

	if _, ok := s.Field("nonexistent"); ok {
		t.Fatal("s.Field says nonexistent field exists")
	}
}

// TestSecretCRUD tests the creation, read, update, and delete of a Secret.
// Referred to as "Test #2" in the README.
func TestSecretCRUD(t *testing.T) {
	runBattery(t, SecretCRUD)
}

func SecretCRUD(t *testing.T, tss *Server) {
	siteId := requireIntEnv(t, "TSS_SITE_ID")
	folderId := requireIntEnv(t, "TSS_FOLDER_ID")
	templateId := requireIntEnv(t, "TSS_TEMPLATE_ID")
	testPassword := requireEnv(t, "TSS_TEST_PASSWORD")

	// Retrieve the template so we know what fields are required
	refSecretTemplate, err := tss.SecretTemplate(templateId)
	if err != nil {
		t.Fatal("calling server.SecretTemplate:", err)
	}

	// Build the fields the template calls for. Every required field must be filled:
	// omitting one earns an "API_RequiredFieldMissing: Secret field is required"
	// from the server, which does not say which field it wanted. Recognized fields
	// get realistic values; any other required field gets a placeholder, so the case
	// works against templates beyond the ones named here.
	var fields []SecretField
	for _, field := range refSecretTemplate.Fields {
		value := ""
		switch {
		case field.IsPassword:
			value = testPassword
		case regexp.MustCompile(`(?i)username`).MatchString(field.FieldSlugName):
			value = "TestUser"
		case regexp.MustCompile(`(?i)url`).MatchString(field.FieldSlugName):
			value = "https://example.com"
		case regexp.MustCompile(`(?i)machine|host`).MatchString(field.FieldSlugName):
			value = "test.example.com"
		case regexp.MustCompile(`(?i)notes`).MatchString(field.FieldSlugName):
			value = "delete after use"
		case field.IsRequired && field.IsFile:
			t.Fatalf("template %d requires the file field %q, which this case cannot generate; "+
				"point TSS_TEMPLATE_ID at a template whose required fields are text",
				templateId, field.FieldSlugName)
		case field.IsRequired:
			value = "test-" + field.FieldSlugName
		}
		if value != "" {
			fields = append(fields, SecretField{
				FieldID:   field.SecretTemplateFieldID,
				ItemValue: value,
			})
		}
	}

	if len(fields) == 0 {
		t.Fatalf("No usable fields found in template %d", templateId)
	}

	// Test creation of a new secret
	refSecret := new(Secret)
	refSecret.Name = "Test Secret"
	refSecret.SiteID = siteId
	refSecret.FolderID = folderId
	refSecret.SecretTemplateID = templateId
	refSecret.Fields = fields

	sc, err := tss.CreateSecret(*refSecret)
	markDeleted := cleanupCreatedSecret(t, tss, sc, err)
	if err != nil {
		t.Fatal("calling server.CreateSecret:", err)
	}
	if sc == nil {
		t.Fatal("created secret data is nil")
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

	// Check password field exists and matches
	var passwordFieldID int
	for _, f := range refSecretTemplate.Fields {
		if f.IsPassword {
			passwordFieldID = f.SecretTemplateFieldID
			break
		}
	}
	createdPassword, matched := sc.FieldById(passwordFieldID)
	if !matched {
		t.Fatalf("created secret does not have a password field with the given field id '%d':", passwordFieldID)
	}
	if !validateSensitive("created secret password value", testPassword, createdPassword, t) {
		return
	}

	// Test the read of the new secret
	sr, err := tss.Secret(sc.ID)
	if err != nil {
		t.Fatal("calling server.Secret:", err)
	}
	if sr == nil {
		t.Fatal("read secret data is nil")
	}

	// Update the password field
	newPassword := testPassword + "updated"
	refSecret.ID = sc.ID
	for i, f := range refSecret.Fields {
		if f.FieldID == passwordFieldID {
			refSecret.Fields[i].ItemValue = newPassword
		}
	}

	su, err := tss.UpdateSecret(*refSecret)
	if err != nil {
		t.Fatal("calling server.UpdateSecret:", err)
	}
	if su == nil {
		t.Fatal("updated secret data is nil")
	}
	updatedPassword, matched := su.FieldById(passwordFieldID)
	if !matched {
		t.Fatalf("updated secret does not have a password field with the given field id '%d':", passwordFieldID)
	}
	if !validateSensitive("updated secret password value", newPassword, updatedPassword, t) {
		return
	}

	// Test the deletion of the new secret
	err = tss.DeleteSecret(sc.ID)
	if err != nil {
		t.Fatal("calling server.DeleteSecret:", err)
	}
	markDeleted()

	// A deleted secret must not come back live. Secret Server refuses the read with
	// API_AccessDenied; a Platform vault keeps the recycled secret readable with Active
	// false. Both are correct, so requiring an error here would fail against a Platform.
	s, err := tss.Secret(sc.ID)
	if err == nil && s == nil {
		t.Errorf("reading deleted secret %d returned neither a secret nor an error", sc.ID)
	}
	if s != nil && s.Active {
		t.Fatalf("deleted secret with id '%d' is still active after deletion", sc.ID)
	}
}

// TestSecretCRUDForSSHTemplate tests the creation, read, update, and delete
// of a Secret which uses an SSH key template, that is, a template with extended
// mappings that support SSH keys. Referred to as "Test #3" in the README.
func TestSecretCRUDForSSHTemplate(t *testing.T) {
	runBattery(t, SecretCRUDForSSHTemplate)
}

func SecretCRUDForSSHTemplate(t *testing.T, tss *Server) {
	siteId := requireIntEnv(t, "TSS_SITE_ID")
	folderId := requireIntEnv(t, "TSS_FOLDER_ID")
	templateId := requireIntEnv(t, "TSS_SSH_KEY_TEMPLATE_ID")
	testPassword := requireEnv(t, "TSS_TEST_PASSWORD")

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
		t.Fatal("calling server.SecretTemplate:", err)
	}
	publicKeyFieldId, privateKeyFieldId, passphraseFieldId := -1, -1, -1
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
	markDeleted := cleanupCreatedSecret(t, tss, sc, err)
	if err != nil {
		t.Fatal("calling server.CreateSecret:", err)
	}
	if sc == nil {
		t.Fatal("created secret data is nil")
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
		if !validateSensitive("created secret password field has the given value", password, passwordField.ItemValue, t) {
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
		t.Fatal("calling server.Secret:", err)
	}
	if sr == nil {
		t.Fatal("read secret data is nil")
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
	if publicKeyField, problem := getField(sr, publicKeyFieldId, t); publicKeyField != nil && !problem {
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
	if privateKeyField, problem := getField(sr, privateKeyFieldId, t); privateKeyField != nil && !problem {
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
	if passphraseField, problem := getField(sr, passphraseFieldId, t); passphraseField != nil && !problem {
		if !validate("read secret passphrase field is a password field", true, passphraseField.IsPassword, t) {
			return
		}
		if !validate("read secret passphrase field has a value", true, len(passphraseField.ItemValue) > 10, t) {
			return
		}
	} else if problem {
		return
	}
	if userNameField, problem := getField(sr, userNameFieldId, t); userNameField != nil && !problem {
		if !validate("read secret username field has the given value", userName, userNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if passwordField, problem := getField(sr, passwordFieldId, t); passwordField != nil && !problem {
		if !validate("read secret password field is a password field", true, passwordField.IsPassword, t) {
			return
		}
		if !validateSensitive("read secret password field has the given value", password, passwordField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if machineNameField, problem := getField(sr, machineNameFieldId, t); machineNameField != nil && !problem {
		if !validate("read secret machine name field has a value", machine, machineNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}

	// Test the update of the new secret
	sc.Name = sc.Name + " (Updated)"
	sc.SshKeyArgs = nil
	su, err := tss.UpdateSecret(*sc)
	if err != nil {
		t.Fatal("calling server.UpdateSecret:", err)
	}
	if su == nil {
		t.Fatal("updated secret data is nil")
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
	if publicKeyField, problem := getField(su, publicKeyFieldId, t); publicKeyField != nil && !problem {
		if !validate("updated secret public key field is a file field", true, publicKeyField.IsFile, t) {
			return
		}
		if !validate("updated secret public key field has a generated value", true, len(publicKeyField.ItemValue) > 100, t) {
			return
		}
		// The update re-uploads the generated file, and uploadFile gives an
		// extensionless name an extension, so the server's "Public Key" comes back as
		// "Public Key.txt". The private key keeps its name because it already had one.
		if !validate("updated secret public key field has a generated file name",
			publicKeyField.FieldName+".txt", publicKeyField.Filename, t) {
			return
		}
	} else if problem {
		return
	}
	if privateKeyField, problem := getField(su, privateKeyFieldId, t); privateKeyField != nil && !problem {
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
	if passphraseField, problem := getField(su, passphraseFieldId, t); passphraseField != nil && !problem {
		if !validate("updated secret passphrase field is a password field", true, passphraseField.IsPassword, t) {
			return
		}
		if !validate("updated secret passphrase field has a value", true, len(passphraseField.ItemValue) > 10, t) {
			return
		}
	} else if problem {
		return
	}
	if userNameField, problem := getField(su, userNameFieldId, t); userNameField != nil && !problem {
		if !validate("updated secret username field has the given value", userName, userNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if passwordField, problem := getField(su, passwordFieldId, t); passwordField != nil && !problem {
		if !validate("updated secret password field is a password field", true, passwordField.IsPassword, t) {
			return
		}
		if !validateSensitive("updated secret password field has the given value", password, passwordField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}
	if machineNameField, problem := getField(su, machineNameFieldId, t); machineNameField != nil && !problem {
		if !validate("updated secret machine name field has a value", machine, machineNameField.ItemValue, t) {
			return
		}
	} else if problem {
		return
	}

	// Test the deletion of the new secret
	err = tss.DeleteSecret(sc.ID)
	if err != nil {
		t.Fatal("calling server.DeleteSecret:", err)
	}
	markDeleted()

	// A deleted secret must not come back live. Secret Server refuses the read with
	// API_AccessDenied; a Platform vault keeps the recycled secret readable with Active
	// false. Both are correct, so requiring an error here would fail against a Platform.
	s, err := tss.Secret(sc.ID)
	if err == nil && s == nil {
		t.Errorf("reading deleted secret %d returned neither a secret nor an error", sc.ID)
	}
	if s != nil && s.Active {
		t.Fatalf("deleted secret with id '%d' is still active after deletion", sc.ID)
	}
}

// TestSearch tests Secret. Referred to as "Test #4" in the README.
func TestSearch(t *testing.T) {
	runBattery(t, Search)
}

func Search(t *testing.T, tss *Server) {

	searchText := requireEnv(t, "TSS_SEARCH_TEXT")
	searchField := requireEnv(t, "TSS_SEARCH_FIELD")

	s, err := tss.Secrets(searchText, searchField)

	if err != nil {
		t.Fatal("calling server.Secret:", err)
	}

	if len(s) == 0 {
		t.Fatal("secret data is nil or empty")
	}

	if _, ok := s[0].Field("password"); !ok {
		t.Error("no password field")
	}
}

// TestSearchWithoutField tests Secret. Referred to as "Test #5" in the README.
func TestSearchWithoutField(t *testing.T) {
	runBattery(t, SearchWithoutField)
}

func SearchWithoutField(t *testing.T, tss *Server) {

	s, err := tss.Secrets(requireEnv(t, "TSS_SEARCH_TEXT"), "")

	if err != nil {
		t.Fatal("calling server.Secret:", err)
	}

	// Fatal, not Error: the next line indexes s[0].
	if len(s) == 0 {
		t.Fatal("secret data is nil or empty")
	}

	if _, ok := s[0].Field("password"); !ok {
		t.Error("no password field")
	}
}

// TestSecretByPath tests Secret. Referred to as "Test #7" in the README.
func TestSecretByPath(t *testing.T) {
	runBattery(t, GetSecretByPath)
}

func GetSecretByPath(t *testing.T, tss *Server) {
	// requireEnv skips or fails when the variable is unset, so secretPath is non-empty.
	secretPath := requireEnv(t, "TSS_SECRET_PATH")

	secret, err := tss.SecretByPath(secretPath)
	if err != nil {
		t.Fatalf("Error retrieving secret by path: %v", err)
	}

	// Fatal, not Error: every assertion below dereferences secret.
	if secret == nil {
		t.Fatal("Expected a secret, got nil")
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

// validate reports whether found equals expected, naming both on failure. It formats
// with %v rather than %q because most of these values are ints and bools, which %q
// renders as "%!q(int=3)". t.Helper points the failure at the assertion rather than
// at this line.
func validate(label string, expected interface{}, found interface{}, t *testing.T) bool {
	t.Helper()
	if expected != found {
		t.Errorf("%s: got %v, want %v", label, found, expected)
		return false
	}
	return true
}

// validateSensitive compares live credential values without copying either value
// into test output on failure.
func validateSensitive(label, expected, found string, t *testing.T) bool {
	t.Helper()
	if expected != found {
		t.Errorf("%s: values differ (got length %d, want length %d)", label, len(found), len(expected))
		return false
	}
	return true
}

// cleanupCreatedSecret registers cleanup before a create error can stop the
// test. A PartialWriteError means the server-side object may exist even though
// CreateSecret did not complete all attachment or refresh steps.
func cleanupCreatedSecret(t *testing.T, server *Server, secret *Secret, createErr error) func() {
	t.Helper()
	id := 0
	if secret != nil {
		id = secret.ID
	}
	var partial *PartialWriteError
	if id == 0 && errors.As(createErr, &partial) {
		id = partial.SecretID
	}
	if id > 0 {
		return deleteAfterTest(t, server, id)
	}
	return func() {}
}

// getField returns the field with the given id, and whether looking it up went wrong.
// Note the second value is NOT the usual comma-ok "found": it reports a *problem*, so
// callers read `if field, problem := getField(...); field != nil && !problem`. A
// fieldId of zero or less means the caller never located that field on the template,
// which is not an error here — it yields (nil, false) so the block is skipped quietly.
func getField(secret *Secret, fieldId int, t *testing.T) (*SecretField, bool) {
	t.Helper()
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
