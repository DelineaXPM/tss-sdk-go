package server

import (
	"encoding/json"
	"fmt"
	"log"
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
	secret := new(Secret)

	if data, err := s.accessResource("GET", resource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secret); err != nil {
			log.Printf("[ERROR] error parsing response from /%s/%d: %q", resource, id, data)
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

			if data, err := s.accessResource("GET", resource, path, nil); err == nil {
				secret.Fields[index].ItemValue = string(data)
			} else {
				return nil, err
			}
		}
	}

	return secret, nil
}

func (s Server) CreateSecret(secret Secret) (*Secret, error) {
	return s.writeSecret(secret, "POST", "/")
}

func (s Server) UpdateSecret(secret Secret) (*Secret, error) {
	if secret.SshKeyArgs != nil && (secret.SshKeyArgs.GenerateSshKeys || secret.SshKeyArgs.GeneratePassphrase) {
		err := fmt.Errorf("[ERROR] SSH key and passphrase generation is only supported during secret creation. "+
			"Could not update the secret named '%s'", secret.Name)
		return nil, err
	}
	secret.SshKeyArgs = nil
	return s.writeSecret(secret, "PUT", strconv.Itoa(secret.ID))
}

func (s Server) writeSecret(secret Secret, method string, path string) (*Secret, error) {
	writtenSecret := new(Secret)

	template, err := s.SecretTemplate(secret.SecretTemplateID)
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

	if data, err := s.accessResource(method, resource, path, secret); err == nil {
		if err = json.Unmarshal(data, writtenSecret); err != nil {
			log.Printf("[ERROR] error parsing response from /%s: %q", resource, data)
			return nil, err
		}
	} else {
		return nil, err
	}

	if err := s.updateFiles(writtenSecret.ID, fileFields); err != nil {
		return nil, err
	}

	return s.Secret(writtenSecret.ID)
}

func (s Server) DeleteSecret(id int) error {
	_, err := s.accessResource("DELETE", resource, strconv.Itoa(id), nil)
	return err
}

// Field returns the value of the field with the name fieldName
func (s Secret) Field(fieldName string) (string, bool) {
	for _, field := range s.Fields {
		if fieldName == field.FieldName || fieldName == field.Slug {
			log.Printf("[DEBUG] field with name '%s' matches '%s'", field.FieldName, fieldName)
			return field.ItemValue, true
		}
	}
	log.Printf("[DEBUG] no matching field for name '%s' in secret '%s'", fieldName, s.Name)
	return "", false
}

// FieldById returns the value of the field with the given field ID
func (s Secret) FieldById(fieldId int) (string, bool) {
	for _, field := range s.Fields {
		if fieldId == field.FieldID {
			log.Printf("[DEBUG] field with name '%s' matches field ID '%d'", field.FieldName, fieldId)
			return field.ItemValue, true
		}
	}
	log.Printf("[DEBUG] no matching field for ID '%d' in secret '%s'", fieldId, s.Name)
	return "", false
}

// updateFiles iterates the list of file fields and if the field's item value is empty,
// deletes the file, otherwise, uploads the contents of the item value as the new/updated
// file attachment.
func (s Server) updateFiles(secretId int, fileFields []SecretField) error {
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
			if _, err := s.accessResource("PATCH", resource, path, input); err != nil {
				return err
			}
		} else {
			if err := s.uploadFile(secretId, element); err != nil {
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
