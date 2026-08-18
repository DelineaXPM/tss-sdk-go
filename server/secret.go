package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// Secret gets the secret with id from the Secret Server of the given tenant
func (s Server) Secret(id int) (*Secret, error) {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.SecretContext(ctx, id)
}

// SecretContext is Secret with caller-controlled cancellation and deadlines.
func (s Server) SecretContext(ctx context.Context, id int) (*Secret, error) {
	return s.secretContext(ctx, id, s.newOperationBudget())
}

func (s Server) secretContext(ctx context.Context, id int, budget *operationBudget) (*Secret, error) {
	secret := new(Secret)

	if data, err := s.accessResourceContextWithBudget(ctx, http.MethodGet, resource, strconv.Itoa(id), nil, budget); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			s.log().Printf("[ERROR] parsing response from /%s/%d: %v (%d-byte body not logged)", resource, id, err, len(data))
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.downloadAttachmentsContext(ctx, secret, budget); err != nil {
		return nil, err
	}

	return secret, nil
}

func (s Server) downloadAttachmentsContext(ctx context.Context, secret *Secret, budget *operationBudget) error {
	for index, element := range secret.Fields {
		if element.IsFile && element.FileAttachmentID != 0 && element.Filename != "" {
			if err := budget.claimAttachment(); err != nil {
				return err
			}
			path := fmt.Sprintf("%d/fields/%s", secret.ID, url.PathEscape(element.Slug))

			if data, err := s.accessResourceContextWithBudget(ctx, http.MethodGet, resource, path, nil, budget); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return err
			}
		}
	}
	return nil
}

// Secret gets the secret with id from the Secret Server of the given tenant
func (s Server) Secrets(searchText, field string) ([]Secret, error) {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.SecretsContext(ctx, searchText, field)
}

// SecretsContext is Secrets with caller-controlled cancellation and deadlines.
func (s Server) SecretsContext(ctx context.Context, searchText, field string) ([]Secret, error) {
	budget := s.newOperationBudget()
	searchResult := new(SearchResult)
	if data, err := s.searchResourcesContextWithBudget(ctx, resource, searchText, field, budget); err == nil {
		if err = json.Unmarshal(data, searchResult); err != nil {
			s.log().Printf("[ERROR] parsing secrets search response: %v (%d-byte body not logged)", err, len(data))
			return nil, err
		}
	} else {
		return nil, err
	}

	searchRecords := searchResult.Records
	secrets := make([]Secret, len(searchRecords))
	for i, record := range searchRecords {
		//secrets returned in search results are not fully populated
		secret, err := s.secretContext(ctx, record.ID, budget)
		if err != nil {
			return nil, err
		}
		secrets[i] = *secret
	}

	return secrets, nil
}

func (s Server) SecretByPath(secretPath string) (*Secret, error) {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.SecretByPathContext(ctx, secretPath)
}

// SecretByPathContext is SecretByPath with caller-controlled cancellation and deadlines.
func (s Server) SecretByPathContext(ctx context.Context, secretPath string) (*Secret, error) {
	budget := s.newOperationBudget()
	secret := new(Secret)
	// Encode the secret path to be safe for URLs
	encodedPath := url.QueryEscape(secretPath)
	queryPath := fmt.Sprintf("0?secretPath=%s", encodedPath)

	// Perform the GET request to the 'secrets' resource with the specified path
	if data, err := s.accessResourceContextWithBudget(ctx, http.MethodGet, resource, queryPath, nil, budget); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			s.log().Printf("[ERROR] parsing secret-by-path response: %v (%d-byte body not logged)", err, len(data))
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.downloadAttachmentsContext(ctx, secret, budget); err != nil {
		return nil, err
	}

	return secret, nil
}

func (s Server) CreateSecret(secret Secret) (*Secret, error) {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.CreateSecretContext(ctx, secret)
}

// CreateSecretContext is CreateSecret with caller-controlled cancellation and deadlines.
func (s Server) CreateSecretContext(ctx context.Context, secret Secret) (*Secret, error) {
	return s.writeSecretContext(ctx, secret, http.MethodPost, "/", s.newOperationBudget())
}

func (s Server) UpdateSecret(secret Secret) (*Secret, error) {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.UpdateSecretContext(ctx, secret)
}

// UpdateSecretContext is UpdateSecret with caller-controlled cancellation and deadlines.
func (s Server) UpdateSecretContext(ctx context.Context, secret Secret) (*Secret, error) {
	if secret.SshKeyArgs != nil && (secret.SshKeyArgs.GenerateSshKeys || secret.SshKeyArgs.GeneratePassphrase) {
		err := fmt.Errorf("[ERROR] SSH key and passphrase generation is only supported during secret creation. "+
			"Could not update the secret named '%s'", secret.Name)
		return nil, err
	}
	secret.SshKeyArgs = nil
	return s.writeSecretContext(ctx, secret, http.MethodPut, strconv.Itoa(secret.ID), s.newOperationBudget())
}

func (s Server) writeSecretContext(ctx context.Context, secret Secret, method, path string, budget *operationBudget) (*Secret, error) {
	writtenSecret := new(Secret)

	template, err := s.secretTemplateContext(ctx, secret.SecretTemplateID, budget)
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
	if secret.SshKeyArgs == nil || !secret.SshKeyArgs.GenerateSshKeys {
		var generalFields []SecretField
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

	if data, err := s.accessResourceContextWithBudget(ctx, method, resource, path, secret, budget); err == nil {
		if err = json.Unmarshal(data, writtenSecret); err != nil {
			s.log().Printf("[ERROR] parsing response from /%s: %v (%d-byte body not logged)", resource, err, len(data))
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.updateFilesContext(ctx, writtenSecret.ID, fileFields, budget); err != nil {
		return nil, err
	}

	return s.secretContext(ctx, writtenSecret.ID, budget)
}

func (s Server) DeleteSecret(id int) error {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.DeleteSecretContext(ctx, id)
}

// DeleteSecretContext is DeleteSecret with caller-controlled cancellation and deadlines.
func (s Server) DeleteSecretContext(ctx context.Context, id int) error {
	_, err := s.accessResourceContextWithBudget(ctx, http.MethodDelete, resource, strconv.Itoa(id), nil, s.newOperationBudget())
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

func (s Server) updateFilesContext(ctx context.Context, secretId int, fileFields []SecretField, budget *operationBudget) error {
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
			if _, err := s.accessResourceContextWithBudget(ctx, http.MethodPatch, resource, path, input, budget); err != nil {
				return err
			}
		} else {
			if err := s.uploadFileContextWithBudget(ctx, secretId, element, budget); err != nil {
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
