package server

import (
	"testing"
)

// TestSecretTemplate tests SecretTemplate
func TestSecretTemplate(t *testing.T) {
	tss, err := initServer()
	if err != nil {
		t.Error("configuring the Server:", err)
		return
	}

	id := initIntegerFromEnv("TSS_TEMPLATE_ID", t)
	if id < 0 {
		return
	}

	template, err := tss.SecretTemplate(id)

	if err != nil {
		t.Error("calling secrets.SecretTemplate:", err)
		return
	}

	if template == nil {
		t.Error("secret data is nil")
	}

	for _, field := range template.Fields {
		fieldSlug := field.FieldSlugName
		fieldID := field.SecretTemplateFieldID

		lookupFieldId, foundFieldId := template.FieldSlugToId(fieldSlug)
		if ! foundFieldId {
			t.Errorf("expected to find the field slug '%s', but FieldSlugToId reported %t", fieldSlug, foundFieldId)
		} else if fieldID != lookupFieldId {
			t.Errorf("expected the field slug '%s' to return a field id of '%d', but '%d' was returned instead", fieldSlug, fieldID, lookupFieldId)
		}

		lookupSlug, foundSlug := template.FieldIdToSlug(fieldID)
		if ! foundSlug {
			t.Errorf("expected to find the field ID '%d', but FieldIdToSlug reported %t", fieldID, foundSlug)
		} else if fieldSlug != lookupSlug {
			t.Errorf("expected the field id '%d' to return a field slug of '%s', but '%s' was returned instead", fieldID, fieldSlug, lookupSlug)
		}

		generatedPassword, err := tss.GeneratePassword(fieldSlug, template)
		if field.IsPassword {
			if len(generatedPassword) == 0 || err != nil {
				t.Errorf("expected to be able to generate a password for the '%s' field; error is '%v'", fieldSlug, err)
			} else {
				t.Logf("generated '%s' for the '%s' field", generatedPassword, fieldSlug)
			}
		} else {
			if len(generatedPassword) > 0 || err == nil {
				t.Errorf("expected an error when generating a password for the '%s' field", fieldSlug)
			}
		}
	}
}
