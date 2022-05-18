package server

import (
	"encoding/json"
	"fmt"
	"log"
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
			log.Printf("[ERROR] error parsing response from /%s/%d: %q", templateResource, id, data)
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
		log.Printf("[ERROR] the alias '%s' does not identify a field on the template named '%s'", slug, template.Name)
	}
	path := fmt.Sprintf("generate-password/%d", fieldId)

	if data, err := s.accessResource("POST", templateResource, path, nil); err == nil {
		passwordWithQuotes := string(data)
		return passwordWithQuotes[1 : len(passwordWithQuotes)-1], nil
	} else {
		return "", err
	}
}

// FieldIdToSlug returns the shorthand alias (aka: "slug") of the field with the given field ID, and a boolean
// indicating whether the given ID actually identifies a field for the secret template.
func (s SecretTemplate) FieldIdToSlug(fieldId int) (string, bool) {
	for _, field := range s.Fields {
		if fieldId == field.SecretTemplateFieldID {
			log.Printf("[TRACE] template field with slug '%s' matches the given ID '%d'", field.FieldSlugName, fieldId)
			return field.FieldSlugName, true
		}
	}
	log.Printf("[ERROR] no matching template field with id '%d' in template '%s'", fieldId, s.Name)
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
			log.Printf("[TRACE] template field with ID '%d' matches the given slug '%s'", field.SecretTemplateFieldID, slug)
			return &field, true
		}
	}
	log.Printf("[ERROR] no matching template field with slug '%s' in template '%s'", slug, s.Name)
	return nil, false
}
