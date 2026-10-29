package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cps-kit/section7"
)

// TestRenderProfile tests the basic profile rendering functionality.
func TestRenderProfile(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Version:  3,
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
	if !strings.Contains(rendered, "## Certificate Profile: Test Profile (X.509v3)") {
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
		Profile: section7.Meta{Name: "Length Test"},
		Requirements: section7.Requirements{
			Version: 3,
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
		Profile: section7.Meta{Name: "Ext Test"},
		Requirements: section7.Requirements{
			Version: 3,
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
		Profile: section7.Meta{Name: "No Length Test"},
		Requirements: section7.Requirements{
			Version: 3,
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
		Profile: section7.Meta{Name: "Subject Test"},
		Requirements: section7.Requirements{
			Version: 3,
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
		Profile: section7.Meta{Name: "Optional Subject"},
		Requirements: section7.Requirements{
			Version: 3,
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

// TestRenderProfileFollowsCertificateOrder checks sections follow the
// TBSCertificate field order and attribute rows follow the encoding order of
// Section 7.1.4.2 of the Baseline Requirements.
func TestRenderProfileFollowsCertificateOrder(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Order Test"},
		Requirements: section7.Requirements{
			Version:            3,
			SerialNumber:       section7.SerialNumber{Required: true, Declared: true},
			SignatureAlgorithm: section7.SignatureAlgorithm{Allowed: []string{"sha256WithRSAEncryption"}},
			Issuer: section7.DistinguishedName{
				Attributes: map[string]section7.Field{"common_name": {Required: true}},
			},
			Validity: section7.Validity{MaximumDays: 398},
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country_name":      {Required: true},
				},
			},
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "rsaEncryption", KeySizes: []int{2048}}},
			},
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Critical: section7.CriticalityRequired},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	inOrder := func(what string, items ...string) {
		t.Helper()
		pos := 0
		for _, item := range items {
			i := strings.Index(rendered[pos:], item)
			if i == -1 {
				t.Errorf("%s: %q should appear after the preceding item, got:\n%s", what, item, rendered)
				return
			}
			pos += i + len(item)
		}
	}

	inOrder("sections",
		"### Serial Number", "### Signature Algorithm", "### Issuer DN Requirements",
		"### Validity", "### Subject DN Requirements", "### Subject Public Key",
		"### Unique Identifiers", "### Extensions")
	if !strings.Contains(rendered, "The `issuerUniqueID` and `subjectUniqueID` fields MUST NOT be present.") {
		t.Errorf("the unique identifier fields should be forbidden in prose, got:\n%s", rendered)
	}
	inOrder("subject attributes",
		"### Subject DN Requirements", "| countryName |", "| organizationName |", "| commonName |")
	if !strings.Contains(rendered, "MUST be present: `countryName`, `organizationName`, `commonName`.") {
		t.Errorf("required attributes should be listed in encoding order, got:\n%s", rendered)
	}
}

// TestRenderProfileAlgorithmsAndIssuer checks the signature algorithm, public
// key and issuer sections are rendered when a profile states them.
func TestRenderProfileAlgorithmsAndIssuer(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Fields Test"},
		Requirements: section7.Requirements{
			Version:            3,
			SignatureAlgorithm: section7.SignatureAlgorithm{Allowed: []string{"ecdsa-with-SHA256"}},
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{
					{Name: "rsaEncryption", KeySizes: []int{2048, 4096}},
					{Name: "id-ecPublicKey", Curves: []string{"P-256"}},
				},
			},
			Issuer: section7.DistinguishedName{
				Attributes: map[string]section7.Field{"common_name": {Required: true}},
			},
		},
	}

	rendered := renderProfile(p, map[string]interface{}{})

	for _, want := range []string{
		"### Signature Algorithm",
		"| ECDSA with SHA-256 | 1.2.840.10045.4.3.2 |",
		"### Subject Public Key",
		"| RSA | 1.2.840.113549.1.1.1 | 2048, 4096 | - |",
		"| Elliptic Curve | 1.2.840.10045.2.1 | - | P-256 |",
		"### Issuer DN Requirements",
		"| commonName | CN | 2.5.4.3 | Yes |",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered profile should contain %q, got:\n%s", want, rendered)
		}
	}
}

// TestRenderProfileEmptyExtensions tests rendering with no extensions and no
// subject attributes.
func TestRenderProfileEmptyExtensions(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Empty Ext Test"},
		Requirements: section7.Requirements{
			Version:  3,
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

// TestExpandFollowsCertificateOrder checks -expand prints the requirements in
// TBSCertificate order and the attributes in encoding order, rather than in
// the alphabetical order the YAML encoder would choose.
func TestExpandFollowsCertificateOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	doc := `
requirements:
  subject:
    attributes:
      common_name:
        required: true
      country_name:
        required: true
  validity:
    maximum_days: 398
  serial_number:
    required: true
  version: v3
  public_key:
    algorithms: [{name: rsaEncryption}]
  signature_algorithm:
    allowed: [sha256WithRSAEncryption]
  issuer:
    attributes: {common_name: {}}
profile:
  name: Order Test
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	var buf bytes.Buffer
	if err := expandProfile(path, &buf); err != nil {
		t.Fatalf("expanding profile: %v", err)
	}
	out := buf.String()

	pos := 0
	for _, item := range []string{
		"profile:", "requirements:", "version: v3", "serial_number:",
		"validity:", "subject:", "country_name:", "common_name:",
	} {
		i := strings.Index(out[pos:], item)
		if i == -1 {
			t.Fatalf("%q should appear after the preceding item, got:\n%s", item, out)
		}
		pos += i + len(item)
	}
}

// Helper function to create an int pointer
func intPtr(i int) *int {
	return &i
}
