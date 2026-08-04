package server

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// templateResource is the HTTP URL path component for the secret templates resource
const templateResource = "secret-templates"

// SecretTemplate represents a secret template from Delinea Secret Server
type SecretTemplate struct {
	Name   string
	ID     int
	Fields []SecretTemplateField
}

// SecretTemplateField is a field in the secret template
type SecretTemplateField struct {
	SecretTemplateFieldID                                   int
	FieldSlugName, DisplayName, Description, Name, ListType string
	IsFile, IsList, IsNotes, IsPassword, IsRequired, IsUrl  bool
}

// SecretTemplate gets the secret template with id from the Secret Server of the given tenant
func (s Server) SecretTemplate(id int) (*SecretTemplate, error) {
	secretTemplate := new(SecretTemplate)

	if data, err := s.accessResource("GET", templateResource, strconv.Itoa(id), nil); err == nil {
		if err = json.Unmarshal(data, secretTemplate); err != nil {
			s.log().Printf("[ERROR] parsing response from /%s/%d: %v (%d-byte body not logged)", templateResource, id, err, len(data))
			return nil, err
		}
	} else {
		return nil, err
	}

	return secretTemplate, nil
}

// GeneratePassword generates and returns a password for the secret field identified by the given slug on the given
// template. The password adheres to the password requirements associated with the field. NOTE: this should only be
// used with fields whose IsPassword property is true.
func (s Server) GeneratePassword(slug string, template *SecretTemplate) (string, error) {
	fieldId, found := template.FieldSlugToId(slug)

	if !found {
		err := fmt.Errorf("the alias '%s' does not identify a field on the template named '%s'", slug, template.Name)
		s.log().Print("[ERROR] ", err)
		return "", err
	}
	path := fmt.Sprintf("generate-password/%d", fieldId)

	data, err := s.accessResource("POST", templateResource, path, nil)
	if err != nil {
		return "", err
	}

	// The endpoint returns a JSON string. Unmarshaling replaces the previous
	// blind strip of the first and last byte, which mishandled escapes and
	// panicked on a response shorter than two bytes. Decoding into *string
	// rejects a JSON null, which unmarshals into a plain string as a no-op and
	// would otherwise be returned as a valid empty password.
	var password *string
	if err := json.Unmarshal(data, &password); err != nil {
		return "", fmt.Errorf("parsing generate-password response: %w", err)
	}
	if password == nil || *password == "" {
		return "", fmt.Errorf("generate-password response contained no password")
	}
	return *password, nil
}

// FieldIdToSlug returns the shorthand alias (aka: "slug") of the field with the given field ID, and a boolean
// indicating whether the given ID actually identifies a field for the secret template.
func (s SecretTemplate) FieldIdToSlug(fieldId int) (string, bool) {
	for _, field := range s.Fields {
		if fieldId == field.SecretTemplateFieldID {
			return field.FieldSlugName, true
		}
	}
	return "", false
}

// FieldSlugToId returns the field ID for the given shorthand alias (aka: "slug") of the field, and a boolean indicating
// whether the given slug actually identifies a field for the secret template.
func (s SecretTemplate) FieldSlugToId(slug string) (int, bool) {
	field, found := s.GetField(slug)
	if found {
		return field.SecretTemplateFieldID, found
	}
	return 0, found
}

// GetField returns the field with the given shorthand alias (aka: "slug"), and a boolean indicating whether the given
// slug actually identifies a field for the secret template .
func (s SecretTemplate) GetField(slug string) (*SecretTemplateField, bool) {
	for _, field := range s.Fields {
		if slug == field.FieldSlugName {
			return &field, true
		}
	}
	return nil, false
}
