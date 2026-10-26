package main

import (
	"strings"
	"testing"

	"github.com/cps-kit/section7"
)

// TestRenderProfile tests the basic profile rendering functionality.
func TestRenderProfile(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile", Version: 3},
		Requirements: section7.Requirements{
			Validity: section7.Validity{MaximumDays: 398},
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true, Length: section7.FieldLength{Min: intPtr(1), Max: intPtr(64)}},
				},
			},
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Critical: section7.CriticalityRequired},
			},
		},
		Rules: []section7.Rule{
			{ID: "TEST-001", Text: "Test rule with {profile.name}"},
		},
	}

	raw := map[string]interface{}{
		"profile": map[string]interface{}{
			"name": "Test Profile",
		},
	}

	rendered := renderProfile(p, raw)

	// Check that key sections are present
	if !strings.Contains(rendered, "## Certificate Profile: Test Profile") {
		t.Error("rendered profile should contain profile name")
	}
	if !strings.Contains(rendered, "### Validity") {
		t.Error("rendered profile should contain Validity section")
	}
	if !strings.Contains(rendered, "### Subject DN Requirements") {
		t.Error("rendered profile should contain Subject section")
	}
	if !strings.Contains(rendered, "### Extensions") {
		t.Error("rendered profile should contain Extensions section")
	}
	if !strings.Contains(rendered, "### Rules") {
		t.Error("rendered profile should contain Rules section")
	}
	if !strings.Contains(rendered, "Test rule with Test Profile") {
		t.Error("rendered profile should have interpolated rule text")
	}
}

// TestRenderProfileWithLengthConstraints tests rendering with min/max length.
func TestRenderProfileWithLengthConstraints(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Length Test", Version: 3},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"country":           {Required: true, Length: section7.FieldLength{Min: intPtr(2), Max: intPtr(2)}},
					"organization_name": {Required: true, Length: section7.FieldLength{Min: intPtr(1), Max: intPtr(64)}},
				},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if !strings.Contains(rendered, "Min Length") {
		t.Error("rendered profile should include Min Length column when constraints exist")
	}
	if !strings.Contains(rendered, "Max Length") {
		t.Error("rendered profile should include Max Length column when constraints exist")
	}
	if !strings.Contains(rendered, "2") || !strings.Contains(rendered, "64") {
		t.Error("rendered profile should display actual length values")
	}
}

// TestRenderProfileExtensionDetails tests extension details rendering.
func TestRenderProfileExtensionDetails(t *testing.T) {
	ca := false
	p := section7.Profile{
		Profile: section7.Meta{Name: "Ext Test", Version: 3},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"basic_constraints":  {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
				"extended_key_usage": {Required: section7.PresenceRequired, Critical: section7.CriticalityForbidden, RequiredValues: []string{"serverAuth", "clientAuth"}},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if !strings.Contains(rendered, "#### Basic Constraints") {
		t.Error("rendered profile should contain a dedicated Basic Constraints section")
	}
	if !strings.Contains(rendered, "#### Extended Key Usage") {
		t.Error("rendered profile should contain a dedicated Extended Key Usage section")
	}
	if !strings.Contains(rendered, "| CA | No |") {
		t.Error("rendered profile should show the CA property as No")
	}
	if !strings.Contains(rendered, "`cA` boolean MUST be set to FALSE") {
		t.Error("rendered profile should spell out the cA requirement")
	}
	if !strings.Contains(rendered, "2.5.29.19") {
		t.Error("rendered profile should include the Basic Constraints OID")
	}
	if !strings.Contains(rendered, "serverAuth") {
		t.Error("rendered profile should list required EKUs")
	}
	if !strings.Contains(rendered, "clientAuth") {
		t.Error("rendered profile should list all required EKUs")
	}
	if !strings.Contains(rendered, "1.3.6.1.5.5.7.3.1") {
		t.Error("rendered profile should include the serverAuth OID")
	}
}

// TestRenderProfileWithoutLengthConstraints tests rendering without min/max length.
func TestRenderProfileWithoutLengthConstraints(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "No Length Test", Version: 3},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name": {Required: true},
				},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if !strings.Contains(rendered, "| Attribute | Short Name | OID | Required |") {
		t.Error("rendered profile should have simple Required column without length columns")
	}
}

// TestRenderProfileSubjectWithRequiredAttributes checks a required attribute
// makes the subject mandatory in prose.
func TestRenderProfileSubjectWithRequiredAttributes(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Subject Test", Version: 3},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"country":           {Required: true, Length: section7.FieldLength{Min: intPtr(2), Max: intPtr(2)}},
					"organization_name": {Required: true, Length: section7.FieldLength{Min: intPtr(1), Max: intPtr(64)}},
				},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if !strings.Contains(rendered, "The subject field MUST contain a non-empty RDNSequence") {
		t.Errorf("a subject with required attributes should be stated as mandatory, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "The following attributes MUST be present: `countryName`, `organizationName`.") {
		t.Errorf("required attributes should be listed in prose, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "| Attribute | Short Name | OID | Required | Min Length | Max Length |") {
		t.Error("the attribute table should use the Attribute column header")
	}
	if !strings.Contains(rendered, "| countryName | C | 2.5.4.6 | Yes | 2 | 2 |") {
		t.Errorf("the table should use X.520 names with short name and OID, got:\n%s", rendered)
	}
}

// TestRenderProfileSubjectWithoutRequiredAttributes checks the wording when the
// subject may be empty.
func TestRenderProfileSubjectWithoutRequiredAttributes(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Optional Subject", Version: 3},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"country": {Required: false},
				},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if !strings.Contains(rendered, "The subject field MAY contain an empty RDNSequence") {
		t.Errorf("a subject without required attributes should be stated as optional, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "MUST include a Subject Alternative Name extension marked critical") {
		t.Errorf("an empty subject should require a critical SAN, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "The following attributes MUST be present") {
		t.Error("no attributes are required, so no such sentence should be rendered")
	}
}

// TestRenderProfileEmptyExtensions tests rendering with no extensions and no
// subject attributes.
func TestRenderProfileEmptyExtensions(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Empty Ext Test", Version: 3},
		Requirements: section7.Requirements{
			Validity: section7.Validity{MaximumDays: 398},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	if strings.Contains(rendered, "### Extensions") {
		t.Error("rendered profile should not have Extensions section when empty")
	}
	if !strings.Contains(rendered, "The subject field MUST be an empty RDNSequence") {
		t.Errorf("a profile listing no subject attributes should require an empty subject, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "MUST include a Subject Alternative Name extension marked critical") {
		t.Errorf("an empty subject should require a critical SAN, got:\n%s", rendered)
	}
}

// Helper function to create an int pointer
func intPtr(i int) *int {
	return &i
}
