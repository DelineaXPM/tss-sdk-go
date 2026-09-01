package server

import (
	"testing"
)

// TestSecretTemplate tests SecretTemplate. Referred to as
// "Test #6" in the README.
func TestSecretTemplate(t *testing.T) {
	runBattery(t, VerifySecretTemplate)
}

// GetField hands out a pointer into the template, so an edit through it is visible on
// the template the caller then sends back to the server.
func TestGetFieldAliasesTheTemplateField(t *testing.T) {
	template := &SecretTemplate{
		Name: "Password",
		ID:   6,
		Fields: []SecretTemplateField{
			{SecretTemplateFieldID: 108, FieldSlugName: "username"},
			{SecretTemplateFieldID: 110, FieldSlugName: "password", IsPassword: true, IsRequired: true},
		},
	}

	field, found := template.GetField("password")
	if !found {
		t.Fatal("GetField did not find the password field")
	}
	if field != &template.Fields[1] {
		t.Error("GetField returned a copy rather than the template's own field")
	}

	field.IsRequired = false
	if template.Fields[1].IsRequired {
		t.Error("an edit through the returned field did not reach the template")
	}
}

func VerifySecretTemplate(t *testing.T, tss *Server) {
	id := requireIntEnv(t, "TSS_TEMPLATE_ID")
	template, err := tss.SecretTemplate(id)

	if err != nil {
		t.Fatal("calling secrets.SecretTemplate:", err)
	}

	if template == nil {
		t.Fatal("secret data is nil")
	}

	for _, field := range template.Fields {
		fieldSlug := field.FieldSlugName
		fieldID := field.SecretTemplateFieldID

		lookupFieldId, foundFieldId := template.FieldSlugToId(fieldSlug)
		if !foundFieldId {
			t.Errorf("expected to find the field slug '%s', but FieldSlugToId reported %t", fieldSlug, foundFieldId)
		} else if fieldID != lookupFieldId {
			t.Errorf("expected the field slug '%s' to return a field id of '%d', but '%d' was returned instead", fieldSlug, fieldID, lookupFieldId)
		}

		lookupSlug, foundSlug := template.FieldIdToSlug(fieldID)
		if !foundSlug {
			t.Errorf("expected to find the field ID '%d', but FieldIdToSlug reported %t", fieldID, foundSlug)
		} else if fieldSlug != lookupSlug {
			t.Errorf("expected the field id '%d' to return a field slug of '%s', but '%s' was returned instead", fieldID, fieldSlug, lookupSlug)
		}

		generatedPassword, err := tss.GeneratePassword(fieldSlug, template)
		if field.IsPassword {
			if len(generatedPassword) == 0 || err != nil {
				t.Errorf("expected to be able to generate a password for the '%s' field; error is '%v'", fieldSlug, err)
			} else {
				// The generated value is a live credential; log its shape, not the value.
				t.Logf("generated a %d-character password for the '%s' field", len(generatedPassword), fieldSlug)
			}
		} else {
			if len(generatedPassword) > 0 || err == nil {
				t.Errorf("expected an error when generating a password for the '%s' field", fieldSlug)
			}
		}
	}
}
