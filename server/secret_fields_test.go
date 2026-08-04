package server

import "testing"

var fieldsTestTemplate = &SecretTemplate{
	Name: "Web Password",
	ID:   6,
	Fields: []SecretTemplateField{
		{SecretTemplateFieldID: 11, FieldSlugName: "username"},
		{SecretTemplateFieldID: 12, FieldSlugName: "password", IsPassword: true},
		{SecretTemplateFieldID: 13, FieldSlugName: "attachment", IsFile: true},
	},
}

func TestSecretFieldLookup(t *testing.T) {
	secret := Secret{Fields: []SecretField{
		{FieldID: 11, FieldName: "User Name", Slug: "username", ItemValue: "bob"},
		{FieldID: 12, FieldName: "Password", Slug: "password", ItemValue: "s3cret"},
	}}

	for _, c := range []struct {
		lookup    string
		wantValue string
		wantFound bool
	}{
		{"User Name", "bob", true},   // by display name
		{"username", "bob", true},    // by slug
		{"password", "s3cret", true}, // by slug
		{"nope", "", false},
	} {
		value, found := secret.Field(c.lookup)
		if found != c.wantFound || value != c.wantValue {
			t.Errorf("Field(%q) = (%q, %v), want (%q, %v)", c.lookup, value, found, c.wantValue, c.wantFound)
		}
	}
}

func TestSecretFieldByIdLookup(t *testing.T) {
	secret := Secret{Fields: []SecretField{
		{FieldID: 11, Slug: "username", ItemValue: "bob"},
		{FieldID: 12, Slug: "password", ItemValue: "s3cret"},
	}}

	if value, found := secret.FieldById(12); !found || value != "s3cret" {
		t.Errorf("FieldById(12) = (%q, %v), want (%q, true)", value, found, "s3cret")
	}
	if value, found := secret.FieldById(99); found || value != "" {
		t.Errorf("FieldById(99) = (%q, %v), want (\"\", false)", value, found)
	}
}

func TestSecretTemplateFieldIdToSlug(t *testing.T) {
	if slug, found := fieldsTestTemplate.FieldIdToSlug(13); !found || slug != "attachment" {
		t.Errorf("FieldIdToSlug(13) = (%q, %v), want (%q, true)", slug, found, "attachment")
	}
	if slug, found := fieldsTestTemplate.FieldIdToSlug(99); found || slug != "" {
		t.Errorf("FieldIdToSlug(99) = (%q, %v), want (\"\", false)", slug, found)
	}
}

// GetField returns a pointer into the template's field list; check it identifies the
// requested field rather than, say, the last one iterated.
func TestSecretTemplateGetField(t *testing.T) {
	field, found := fieldsTestTemplate.GetField("password")
	if !found {
		t.Fatal("GetField(password) reported not found")
	}
	if field.SecretTemplateFieldID != 12 || !field.IsPassword {
		t.Errorf("GetField(password) = %+v, want the field with ID 12 and IsPassword true", *field)
	}

	if _, found := fieldsTestTemplate.GetField("missing"); found {
		t.Error("GetField(missing) reported found, want not found")
	}
}

// separateFileFields drives whether an attachment is uploaded or deleted, so both the
// split and its two error paths are pinned.
func TestSeparateFileFieldsSplitsByTemplate(t *testing.T) {
	secret := Secret{Fields: []SecretField{
		{Slug: "username", ItemValue: "bob"},
		{Slug: "attachment", ItemValue: "file body"},
	}}

	fileFields, generalFields, err := secret.separateFileFields(fieldsTestTemplate)
	if err != nil {
		t.Fatalf("separateFileFields returned error: %v", err)
	}
	if len(fileFields) != 1 || fileFields[0].Slug != "attachment" {
		t.Errorf("fileFields = %+v, want only the attachment field", fileFields)
	}
	if len(generalFields) != 1 || generalFields[0].Slug != "username" {
		t.Errorf("generalFields = %+v, want only the username field", generalFields)
	}
}

// A field carrying only a FieldID must be resolved to its slug through the template.
func TestSeparateFileFieldsResolvesFieldIdWhenSlugEmpty(t *testing.T) {
	secret := Secret{Fields: []SecretField{{FieldID: 13, ItemValue: "file body"}}}

	fileFields, generalFields, err := secret.separateFileFields(fieldsTestTemplate)
	if err != nil {
		t.Fatalf("separateFileFields returned error: %v", err)
	}
	if len(fileFields) != 1 {
		t.Errorf("fileFields = %+v, want the field resolved to the file slug 'attachment'", fileFields)
	}
	if len(generalFields) != 0 {
		t.Errorf("generalFields = %+v, want none", generalFields)
	}
}

func TestSeparateFileFieldsRejectsUnknownField(t *testing.T) {
	unknownID := Secret{Fields: []SecretField{{FieldID: 99}}}
	if _, _, err := unknownID.separateFileFields(fieldsTestTemplate); err == nil {
		t.Error("expected an error for a field ID absent from the template, got nil")
	}

	unknownSlug := Secret{Fields: []SecretField{{Slug: "not-on-template"}}}
	if _, _, err := unknownSlug.separateFileFields(fieldsTestTemplate); err == nil {
		t.Error("expected an error for a slug absent from the template, got nil")
	}
}
