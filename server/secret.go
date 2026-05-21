package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// resource is the HTTP URL path component for the secrets resource
const resource = "secrets"

// Secret represents a secret from Delinea Secret Server
type Secret struct {
	Name                                                                       string
	FolderID, ID, SiteID, SecretTemplateID                                     int
	SecretPolicyID, PasswordTypeWebScriptID                                    int `json:",omitempty"`
	LauncherConnectAsSecretID, CheckOutIntervalMinutes                         int
	Active, CheckedOut, CheckOutEnabled                                        bool
	AutoChangeEnabled, CheckOutChangePasswordEnabled, DelayIndexing            bool
	EnableInheritPermissions, EnableInheritSecretPolicy, ProxyEnabled          bool
	RequiresComment, SessionRecordingEnabled, WebLauncherRequiresIncognitoMode bool
	Fields                                                                     []SecretField `json:"Items"`
	SshKeyArgs                                                                 *SshKeyArgs   `json:",omitempty"`
}

// SecretField is an item (field) in the secret
type SecretField struct {
	ItemID, FieldID, FileAttachmentID     int
	FieldName, Slug                       string
	FieldDescription, Filename, ItemValue string
	IsFile, IsNotes, IsPassword           bool
}

type SearchResult struct {
	SearchText string
	Records    []Secret
}

// SshKeyArgs control whether to generate an SSH key pair and a private key
// passphrase when the secret template supports such generation.
//
// WARNING: this struct is only used for write _request_ bodies, and will not
// be present in _response_ bodies.
type SshKeyArgs struct {
	GeneratePassphrase, GenerateSshKeys bool
}

// Secret gets the secret with id from the Secret Server of the given tenant.
// It uses context.Background() internally; use SecretWithContext to supply a context.
func (s Server) Secret(id int) (*Secret, error) {
	return s.SecretWithContext(context.Background(), id)
}

// SecretWithContext gets the secret with id from the Secret Server of the given tenant.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) SecretWithContext(ctx context.Context, id int) (*Secret, error) {
	secret := new(Secret)

	if data, err := s.accessResource(ctx, "GET", resource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			s.log().Printf("[ERROR] error parsing response from /%s/%d: %q", resource, id, data)
			return nil, err
		}
	} else {
		return nil, err
	}

	// automatically download file attachments and substitute them for the
	// (dummy) ItemValue, so as to make the process transparent to the caller
	for index, element := range secret.Fields {
		if element.IsFile && element.FileAttachmentID != 0 && element.Filename != "" {
			path := fmt.Sprintf("%d/fields/%s", id, element.Slug)

			if data, err := s.accessResource(ctx, "GET", resource, path, nil); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return nil, err
			}
		}
	}

	return secret, nil
}

// Secrets searches for secrets matching searchText and returns them fully populated.
// It uses context.Background() internally; use SecretsWithContext to supply a context.
func (s Server) Secrets(searchText, field string) ([]Secret, error) {
	return s.SecretsWithContext(context.Background(), searchText, field)
}

// SecretsWithContext searches for secrets matching searchText and returns them fully populated.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) SecretsWithContext(ctx context.Context, searchText, field string) ([]Secret, error) {
	searchResult := new(SearchResult)
	if data, err := s.searchResources(ctx, resource, searchText, field); err == nil {
		if err = json.Unmarshal(data, searchResult); err != nil {
			s.log().Printf("[ERROR] error parsing response from /%s/%s: %q", resource, searchText, data)
			return nil, err
		}
	} else {
		return nil, err
	}

	searchRecords := searchResult.Records
	secrets := make([]Secret, len(searchRecords))
	for i, record := range searchRecords {
		//secrets returned in search results are not fully populated
		secret, err := s.SecretWithContext(ctx, record.ID)
		if err != nil {
			return nil, err
		}
		secrets[i] = *secret
	}

	return secrets, nil
}

// SecretByPath gets the secret at the given path from the Secret Server of the given tenant.
// It uses context.Background() internally; use SecretByPathWithContext to supply a context.
func (s Server) SecretByPath(secretPath string) (*Secret, error) {
	return s.SecretByPathWithContext(context.Background(), secretPath)
}

// SecretByPathWithContext gets the secret at the given path from the Secret Server of the given tenant.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) SecretByPathWithContext(ctx context.Context, secretPath string) (*Secret, error) {
	secret := new(Secret)
	// Encode the secret path to be safe for URLs
	encodedPath := url.QueryEscape(secretPath)
	queryPath := fmt.Sprintf("0?secretPath=%s", encodedPath)

	// Perform the GET request to the 'secrets' resource with the specified path
	if data, err := s.accessResource(ctx, "GET", resource, queryPath, nil); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			s.log().Printf("[ERROR] error parsing response from /%s/%s: %q", resource, secretPath, data)
			return nil, err
		}
	} else {
		return nil, err
	}

	// automatically download file attachments and substitute them for the
	// (dummy) ItemValue, to make the process transparent to the caller
	for index, element := range secret.Fields {
		if element.IsFile && element.FileAttachmentID != 0 && element.Filename != "" {
			path := fmt.Sprintf("%d/fields/%s", secret.ID, element.Slug)

			if data, err := s.accessResource(ctx, "GET", resource, path, nil); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return nil, err
			}
		}
	}

	return secret, nil
}

// CreateSecret creates a new secret and returns it.
// It uses context.Background() internally; use CreateSecretWithContext to supply a context.
func (s Server) CreateSecret(secret Secret) (*Secret, error) {
	return s.CreateSecretWithContext(context.Background(), secret)
}

// CreateSecretWithContext creates a new secret and returns it.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) CreateSecretWithContext(ctx context.Context, secret Secret) (*Secret, error) {
	return s.writeSecret(ctx, secret, "POST", "/")
}

// UpdateSecret updates an existing secret and returns it.
// It uses context.Background() internally; use UpdateSecretWithContext to supply a context.
func (s Server) UpdateSecret(secret Secret) (*Secret, error) {
	return s.UpdateSecretWithContext(context.Background(), secret)
}

// UpdateSecretWithContext updates an existing secret and returns it.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) UpdateSecretWithContext(ctx context.Context, secret Secret) (*Secret, error) {
	if secret.SshKeyArgs != nil && (secret.SshKeyArgs.GenerateSshKeys || secret.SshKeyArgs.GeneratePassphrase) {
		err := fmt.Errorf("[ERROR] SSH key and passphrase generation is only supported during secret creation. "+
			"Could not update the secret named '%s'", secret.Name)
		return nil, err
	}
	secret.SshKeyArgs = nil
	return s.writeSecret(ctx, secret, "PUT", strconv.Itoa(secret.ID))
}

func (s Server) writeSecret(ctx context.Context, secret Secret, method string, path string) (*Secret, error) {
	writtenSecret := new(Secret)

	template, err := s.SecretTemplateWithContext(ctx, secret.SecretTemplateID)
	if err != nil {
		return nil, err
	}

	// If the user did not request SSH key generation, separate the
	// secret's fields into file fields and general fields, since we
	// need to take active control of either providing the files'
	// contents or deleting them. Otherwise, SSH key generation is
	// responsible for populating the contents of the file fields.
	//
	// NOTE!!! This implies support for *either* file contents provided
	// by the SSH generator *or* file contents provided by the user.
	// This SDK does support secret templates that accept both kinds
	// of file fields.
	fileFields := make([]SecretField, 0)
	generalFields := make([]SecretField, 0)
	if secret.SshKeyArgs == nil || !secret.SshKeyArgs.GenerateSshKeys {
		fileFields, generalFields, err = secret.separateFileFields(template)
		if err != nil {
			return nil, err
		}
		secret.Fields = generalFields
	}

	// If no SSH generation is called for, remove the SshKeyArgs value.
	// Simply having the value in the Secret object causes the
	// server to throw an error if the template is not geared towards
	// SSH key generation, even if both of the struct's members are
	// false.
	if secret.SshKeyArgs != nil {
		if !secret.SshKeyArgs.GenerateSshKeys && !secret.SshKeyArgs.GeneratePassphrase {
			secret.SshKeyArgs = nil
		}
	}

	// If the user specifies no items, perhaps because all the fields are
	// generated, apply an empty array to keep the server from rejecting the
	// request for missing a required element.
	if secret.Fields == nil {
		secret.Fields = make([]SecretField, 0)
	}

	if data, err := s.accessResource(ctx, method, resource, path, secret); err == nil {
		if err = json.Unmarshal(data, writtenSecret); err != nil {
			s.log().Printf("[ERROR] error parsing response from /%s: %q", resource, data)
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.updateFiles(ctx, writtenSecret.ID, fileFields); err != nil {
		return nil, err
	}

	return s.SecretWithContext(ctx, writtenSecret.ID)
}

// DeleteSecret deletes the secret with id from the Secret Server of the given tenant.
// It uses context.Background() internally; use DeleteSecretWithContext to supply a context.
func (s Server) DeleteSecret(id int) error {
	return s.DeleteSecretWithContext(context.Background(), id)
}

// DeleteSecretWithContext deletes the secret with id from the Secret Server of the given tenant.
// The provided context controls cancellation and deadlines for all HTTP requests made.
func (s Server) DeleteSecretWithContext(ctx context.Context, id int) error {
	_, err := s.accessResource(ctx, "DELETE", resource, strconv.Itoa(id), nil)
	return err
}

// Field returns the value of the field with the name fieldName
func (s Secret) Field(fieldName string) (string, bool) {
	for _, field := range s.Fields {
		if fieldName == field.FieldName || fieldName == field.Slug {
			return field.ItemValue, true
		}
	}
	return "", false
}

// FieldById returns the value of the field with the given field ID
func (s Secret) FieldById(fieldId int) (string, bool) {
	for _, field := range s.Fields {
		if fieldId == field.FieldID {
			return field.ItemValue, true
		}
	}
	return "", false
}

// updateFiles iterates the list of file fields and if the field's item value is empty,
// deletes the file, otherwise, uploads the contents of the item value as the new/updated
// file attachment.
// ctx controls cancellation and deadlines for all HTTP requests made within this call.
func (s Server) updateFiles(ctx context.Context, secretId int, fileFields []SecretField) error {
	type fieldMod struct {
		Slug  string
		Dirty bool
		Value interface{}
	}

	type fieldMods struct {
		SecretFields []fieldMod
	}

	type secretPatch struct {
		Data fieldMods
	}

	for _, element := range fileFields {
		var path string
		var input interface{}
		if element.ItemValue == "" {
			path = fmt.Sprintf("%d/general", secretId)
			input = secretPatch{Data: fieldMods{SecretFields: []fieldMod{{Slug: element.Slug, Dirty: true, Value: nil}}}}
			if _, err := s.accessResource(ctx, "PATCH", resource, path, input); err != nil {
				return err
			}
		} else {
			if err := s.uploadFile(ctx, secretId, element); err != nil {
				return err
			}
		}
	}
	return nil
}

// separateFileFields iterates the fields on this secret, and separates them into file
// fields and non-file fields, using the field definitions in the given template as a
// guide. File fields are returned as the first output, non file fields as the second
// output.
func (s Secret) separateFileFields(template *SecretTemplate) ([]SecretField, []SecretField, error) {
	var fileFields []SecretField
	var nonFileFields []SecretField

	for _, field := range s.Fields {
		var templateField *SecretTemplateField
		var found bool
		fieldSlug := field.Slug
		if fieldSlug == "" {
			if fieldSlug, found = template.FieldIdToSlug(field.FieldID); !found {
				return nil, nil, fmt.Errorf("[ERROR] field id '%d' is not defined on the secret template with id '%d'", field.FieldID, template.ID)
			}
		}
		if templateField, found = template.GetField(fieldSlug); !found {
			return nil, nil, fmt.Errorf("[ERROR] field name '%s' is not defined on the secret template with id '%d'", fieldSlug, template.ID)
		}
		if templateField.IsFile {
			fileFields = append(fileFields, field)
		} else {
			nonFileFields = append(nonFileFields, field)
		}
	}

	return fileFields, nonFileFields, nil
}
