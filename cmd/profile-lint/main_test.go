package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"section7/internal/profile"
)

// Helper function to create a test certificate
func createTestCert(cn, o, c string, maxValidity int, isCA bool, ekus []x509.ExtKeyUsage) (*x509.Certificate, []byte) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{o},
			Country:      []string{c},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(maxValidity) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           ekus,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return template, certPEM
}

// createParsedTestCert builds a certificate and returns it as parsed from DER.
// Allow-list checks inspect Subject.Names and Extensions, which are only
// populated by parsing, not by the template used to create the certificate.
func createParsedTestCert(t *testing.T, cn, o, c string, ekus []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()

	_, certPEM := createTestCert(cn, o, c, 30, false, ekus)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block produced by createTestCert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// createCertWithSKI builds a parsed leaf certificate that carries a Subject
// Key Identifier. Go only emits one automatically for CA certificates, so the
// template sets it explicitly.
func createCertWithSKI(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// createCertWithAIA builds a parsed certificate carrying an Authority
// Information Access extension with the requested access locations. Passing an
// empty slice omits that access method.
func createCertWithAIA(t *testing.T, ocsp, caIssuers []string) *x509.Certificate {
	t.Helper()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		OCSPServer:            ocsp,
		IssuingCertificateURL: caIssuers,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// createEmptySubjectCert builds a certificate whose Subject DN is an empty
// SEQUENCE, i.e. carries no attributes at all.
func createEmptySubjectCert(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// TestLintValidCertificate tests linting a certificate that meets all requirements.
func TestLintValidCertificate(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Validity: profile.Validity{MaximumDays: 365},
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	findings := lint(cert, p)

	// Should have some info findings
	errors := 0
	for _, f := range findings {
		if f.Severity == Error {
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("Valid certificate should not have errors, got %d", errors)
		for _, f := range findings {
			if f.Severity == Error {
				t.Logf("  Error: %s", f)
			}
		}
	}
}

// TestLintValidityViolation tests detection of validity period violation.
func TestLintValidityViolation(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Validity: profile.Validity{MaximumDays: 10}, // Very short
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil) // 30 day cert

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "validity") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect validity violation")
	}
}

// TestLintMissingRequiredSubjectField tests detection of missing required subject field.
func TestLintMissingRequiredSubjectField(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"locality": {Required: true}, // Not in our test cert
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "locality") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect missing required locality field")
	}
}

// TestLintSubjectFieldLength tests subject field length validation.
func TestLintSubjectFieldLength(t *testing.T) {
	maxLen := 5
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"organization_name": {Required: true, Length: profile.FieldLength{Max: &maxLen}},
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "This is a very long org name", "US", 30, false, nil)

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "exceeds maximum length") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect organization name length violation")
	}
}

// TestLintSubjectLengthCountsCharactersNotBytes guards against measuring
// lengths in bytes. RFC 5280 upper bounds are expressed in characters, so a
// value containing multi-byte characters (here U+2019 RIGHT SINGLE QUOTATION
// MARK, 3 bytes in UTF-8) must not be rejected for exceeding the limit.
func TestLintSubjectLengthCountsCharactersNotBytes(t *testing.T) {
	maxLen := 64
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"organization_name": {Required: true, Length: profile.FieldLength{Max: &maxLen}},
				},
			},
		},
	}

	// 64 characters, but 66 bytes in UTF-8.
	org := "The Workers’ Compens. Rating and Inspec. Bureau of Massachusetts"
	if got := utf8.RuneCountInString(org); got != 64 {
		t.Fatalf("test fixture should be 64 characters, got %d", got)
	}
	if len(org) != 66 {
		t.Fatalf("test fixture should be 66 bytes, got %d", len(org))
	}

	cert, _ := createTestCert("example.com", org, "US", 30, false, nil)

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("a 64-character value must not violate a 64-character limit, got: %s", f)
		}
	}
}

// TestLintSubjectLengthTooLongInCharacters verifies the limit is still enforced
// when the value genuinely exceeds it in characters.
func TestLintSubjectLengthTooLongInCharacters(t *testing.T) {
	maxLen := 5
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"organization_name": {Required: true, Length: profile.FieldLength{Max: &maxLen}},
				},
			},
		},
	}

	// 6 characters (12 bytes) against a 5-character limit.
	cert, _ := createTestCert("example.com", "ééééék", "US", 30, false, nil)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "SUBJECT-003" && f.Severity == Error {
			found = true
			if !strings.Contains(f.Message, "actual: 6 characters") {
				t.Errorf("the message should report the character count, got: %s", f)
			}
		}
	}
	if !found {
		t.Error("a value longer than the limit in characters should be rejected")
	}
}

// TestLintSubjectMinLengthCountsCharacters verifies the minimum bound is also
// measured in characters.
func TestLintSubjectMinLengthCountsCharacters(t *testing.T) {
	minLen := 3
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"organization_name": {Required: true, Length: profile.FieldLength{Min: &minLen}},
				},
			},
		},
	}

	// 2 characters but 6 bytes: must still fail a 3-character minimum.
	cert, _ := createTestCert("example.com", "éé", "US", 30, false, nil)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "SUBJECT-002" && f.Severity == Error {
			found = true
		}
	}
	if !found {
		t.Error("a 2-character value should fail a 3-character minimum despite being 6 bytes")
	}
}

// hasFinding reports whether a finding with the given rule ID and severity exists.
func hasFinding(findings []Finding, ruleID string, sev Severity) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Severity == sev {
			return true
		}
	}
	return false
}

// TestLintRequiredSubjectPresent checks SUBJECT-000 passes for a populated DN.
func TestLintRequiredSubjectPresent(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{Required: true},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := lint(cert, p)

	if !hasFinding(findings, "SUBJECT-000", Info) {
		t.Errorf("a populated subject should satisfy the subject requirement, got: %v", findings)
	}
	if hasFinding(findings, "SUBJECT-000", Error) {
		t.Error("a populated subject should not raise a subject error")
	}
}

// TestLintRequiredSubjectMissing checks SUBJECT-000 does not fail for an empty DN
// when the profile marks the subject as required but allows it to be null.
func TestLintRequiredSubjectMissing(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{Required: true},
		},
	}

	cert := createEmptySubjectCert(t)

	findings := lint(cert, p)

	if hasFinding(findings, "SUBJECT-000", Error) {
		t.Errorf("an empty subject should be accepted when required is set, got: %v", findings)
	}
	if hasFinding(findings, "SUBJECT-001", Error) {
		t.Errorf("subject attribute checks should be skipped for an empty subject, got: %v", findings)
	}
}

// TestLintRequiredSubjectMissingRejectsEmptyDN checks the default behavior: a
// required subject is still rejected when empty unless the profile explicitly
// allows empty DNs.
func TestLintRequiredSubjectMissingRejectsEmptyDN(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{Required: true},
		},
	}

	cert := createEmptySubjectCert(t)

	findings := lint(cert, p)

	if !hasFinding(findings, "SUBJECT-000", Error) {
		t.Fatalf("an empty subject should fail unless allow_empty is set, got: %v", findings)
	}
}

// TestLintRequiredSubjectMissingAllowed checks that an empty DN is accepted when
// the profile explicitly allows it.
func TestLintRequiredSubjectMissingAllowed(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{Required: true, AllowEmpty: true},
		},
	}

	cert := createEmptySubjectCert(t)

	findings := lint(cert, p)

	if hasFinding(findings, "SUBJECT-000", Error) {
		t.Fatalf("an empty subject should be accepted when allow_empty is true, got: %v", findings)
	}
	if hasFinding(findings, "SUBJECT-001", Error) {
		t.Fatalf("subject attribute checks should be skipped for an empty subject, got: %v", findings)
	}
}

// TestLintOptionalSubjectMissing checks that an absent, optional subject is
// accepted and that its attribute requirements are not applied.
func TestLintOptionalSubjectMissing(t *testing.T) {
	ca := false
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: false,
				Attributes: map[string]profile.Field{
					"organization_name": {Required: true},
				},
			},
			Extensions: map[string]profile.Extension{
				"basic_constraints": {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, CA: &ca},
				"key_usage":         {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, RequiredValues: []string{"digitalSignature"}},
			},
		},
	}

	cert := createEmptySubjectCert(t)

	findings := lint(cert, p)

	for _, f := range findings {
		if f.Severity == Error {
			t.Errorf("an optional, absent subject should not produce errors, got: %s", f)
		}
	}
}

// TestLintSubjectAttributesStillCheckedWhenPresent verifies attribute rules
// apply when an optional subject is in fact present.
func TestLintSubjectAttributesStillCheckedWhenPresent(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: false,
				Attributes: map[string]profile.Field{
					"locality": {Required: true}, // not present in the test cert
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := lint(cert, p)

	if !hasFinding(findings, "SUBJECT-001", Error) {
		t.Errorf("attribute requirements should still apply to a present subject, got: %v", findings)
	}
}

// TestLintCAViolation tests detection of CA constraint violation.
func TestLintCAViolation(t *testing.T) {
	ca := false
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"basic_constraints": {Critical: profile.CriticalityRequired, CA: &ca},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, true, nil) // isCA=true

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "CA=") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect CA constraint violation")
	}
}

// TestLintExtendedKeyUsageViolation tests detection of missing extended key usage.
func TestLintExtendedKeyUsageViolation(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"extended_key_usage": {
					Critical:       profile.CriticalityForbidden,
					RequiredValues: []string{"clientAuth"},
				},
			},
		},
	}

	// Create cert without clientAuth
	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "clientAuth") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect missing clientAuth EKU")
	}
}

// TestLintKeyUsageViolation tests detection of missing key usage.
func TestLintKeyUsageViolation(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"key_usage": {
					Critical:       profile.CriticalityRequired,
					RequiredValues: []string{"keyCertSign"},
				},
			},
		},
	}

	// Create cert with default key usage (no keyCertSign)
	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == Error && strings.Contains(f.Message, "keyCertSign") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Should detect missing keyCertSign key usage")
	}
}

// ---------- Allow-list enforcement ----------

// TestLintRejectsUnlistedSubjectAttribute verifies that an attribute present in
// the certificate but absent from the profile is reported.
func TestLintRejectsUnlistedSubjectAttribute(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"common_name": {Required: true},
					// organization_name and country are deliberately omitted.
				},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	findings := lint(cert, p)

	var unlisted []string
	for _, f := range findings {
		if f.RuleID == "SUBJECT-004" && f.Severity == Error {
			unlisted = append(unlisted, f.Message)
		}
	}
	if len(unlisted) != 2 {
		t.Fatalf("expected organization_name and country to be rejected, got: %v", unlisted)
	}
	joined := strings.Join(unlisted, " ")
	for _, want := range []string{"organizationName", "countryName", "2.5.4.10", "2.5.4.6"} {
		if !strings.Contains(joined, want) {
			t.Errorf("message should mention %q, got: %v", want, unlisted)
		}
	}
}

// TestLintAllowsListedSubjectAttributes verifies no false positives when every
// present attribute is listed.
func TestLintAllowsListedSubjectAttributes(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: profile.Subject{
				Required: true,
				Attributes: map[string]profile.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range lint(cert, p) {
		if f.RuleID == "SUBJECT-004" {
			t.Errorf("listed attributes must not be reported, got: %s", f)
		}
	}
}

// TestLintProfileWithoutSubjectPermitsNoAttributes verifies that saying nothing
// about the subject is the strict answer, not the permissive one: a profile
// with no subject block permits no subject attributes.
func TestLintProfileWithoutSubjectPermitsNoAttributes(t *testing.T) {
	p := profile.Profile{
		Profile:      profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	var unlisted []string
	for _, f := range lint(cert, p) {
		if f.RuleID == "SUBJECT-004" && f.Severity == Error {
			unlisted = append(unlisted, f.Message)
		}
	}
	if len(unlisted) != 3 {
		t.Fatalf("every attribute in the certificate should be reported, got: %v", unlisted)
	}
}

// TestLintRejectsUnlistedExtension verifies that an extension present in the
// certificate but absent from the profile is reported.
func TestLintRejectsUnlistedExtension(t *testing.T) {
	ca := false
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"basic_constraints": {Critical: profile.CriticalityRequired, CA: &ca},
				// key_usage and extended_key_usage deliberately omitted.
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	var unlisted []string
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-009" && f.Severity == Error {
			unlisted = append(unlisted, f.Message)
		}
	}

	joined := strings.Join(unlisted, " ")
	for _, want := range []string{"key_usage", "2.5.29.15", "extended_key_usage", "2.5.29.37"} {
		if !strings.Contains(joined, want) {
			t.Errorf("message should mention %q, got: %v", want, unlisted)
		}
	}
}

// TestLintAllowsListedExtensions verifies no false positives when every present
// extension is listed.
func TestLintAllowsListedExtensions(t *testing.T) {
	ca := false
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"basic_constraints":  {Critical: profile.CriticalityRequired, CA: &ca},
				"key_usage":          {RequiredValues: []string{"digitalSignature"}},
				"extended_key_usage": {RequiredValues: []string{"serverAuth"}},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-009" {
			t.Errorf("listed extensions must not be reported, got: %s", f)
		}
	}
}

// TestLintProfileWithoutExtensionsPermitsNone verifies that a profile with no
// extensions block permits no extensions, rather than permitting every one.
func TestLintProfileWithoutExtensionsPermitsNone(t *testing.T) {
	p := profile.Profile{
		Profile:      profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	var unlisted []string
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-009" && f.Severity == Error {
			unlisted = append(unlisted, f.Message)
		}
	}
	if len(unlisted) != len(cert.Extensions) {
		t.Fatalf("every extension in the certificate should be reported, got: %v", unlisted)
	}
}

// TestLintExtensionAcceptedByOID verifies an extension may be listed by raw OID.
func TestLintExtensionAcceptedByOID(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"2.5.29.19": {Critical: profile.CriticalityRequired}, // basic constraints, by OID
				"2.5.29.15": {},                                      // key usage, by OID
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-009" {
			t.Errorf("extensions listed by OID must be accepted, got: %s", f)
		}
	}
}

// ---------- Serial number ----------

func TestLintSerialNumberRequiredOK(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			SerialNumber: profile.SerialNumber{Required: true, Declared: true},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	if !hasFinding(lint(cert, p), "SERIAL-001", Info) {
		t.Error("a positive serial number should satisfy the requirement")
	}
}

func TestLintSerialNumberZeroRejected(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			SerialNumber: profile.SerialNumber{Required: true, Declared: true},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)
	cert.SerialNumber = big.NewInt(0)

	if !hasFinding(lint(cert, p), "SERIAL-001", Error) {
		t.Error("a zero serial number should be rejected")
	}
}

// ---------- Criticality ----------

// TestLintCriticalityCheckedForAllExtensions guards against the criticality
// check only covering a hard-coded set of extensions. Go emits Subject Key
// Identifier as non-critical, so a profile demanding critical=true must fail.
func TestLintCriticalityCheckedForAllExtensions(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"subject_key_identifier": {Critical: profile.CriticalityRequired},
			},
		},
	}

	cert := createCertWithSKI(t)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == Error &&
			strings.Contains(f.Message, "subject_key_identifier") {
			found = true
		}
	}
	if !found {
		t.Error("a non-critical subject_key_identifier must fail a profile requiring critical=true")
	}
}

// TestLintCriticalityAcceptedForAllExtensions is the matching positive case.
func TestLintCriticalityAcceptedForAllExtensions(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"subject_key_identifier": {Critical: profile.CriticalityForbidden},
			},
		},
	}

	cert := createCertWithSKI(t)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == Error {
			t.Errorf("a matching criticality must not be reported, got: %s", f)
		}
	}
}

// TestLintCriticalityCheckedForOIDKeyedExtension verifies the check also works
// when the extension is listed by raw OID.
func TestLintCriticalityCheckedForOIDKeyedExtension(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"2.5.29.14": {Critical: profile.CriticalityRequired}, // subject key identifier, by OID
			},
		},
	}

	cert := createCertWithSKI(t)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == Error {
			found = true
		}
	}
	if !found {
		t.Error("criticality must be checked for extensions listed by OID")
	}
}

// TestLintAbsentListedExtensionReported verifies that a listed but absent
// extension is reported rather than silently skipped.
func TestLintAbsentListedExtensionReported(t *testing.T) {
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"name_constraints": {Critical: profile.CriticalityRequired}, // not present in the test cert
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-010" && strings.Contains(f.Message, "name_constraints") {
			found = true
		}
		if f.RuleID == "EXT-002" && strings.Contains(f.Message, "name_constraints") {
			t.Errorf("an absent extension must not be judged on criticality, got: %s", f)
		}
	}
	if !found {
		t.Error("an absent but permitted extension should be reported as such")
	}
}

// TestLintPolicyUnderArcAccepted verifies a policy beneath a permitted arc is
// accepted rather than reported as unlisted.
func TestLintPolicyUnderArcAccepted(t *testing.T) {
	p := policyArcProfile()
	cert := createCertWithPolicies(t, "2.23.140.1.2.1", "1.3.6.1.4.1.6449.1.2.2.7")

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("a policy under a permitted arc must not error, got: %s", f)
		}
	}

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-016" && strings.Contains(f.Message, "permitted by arc") {
			found = true
		}
	}
	if !found {
		t.Error("an arc-permitted policy should be reported as such")
	}
}

// TestLintPolicyOutsideArcRejected verifies an unrelated policy is still caught.
func TestLintPolicyOutsideArcRejected(t *testing.T) {
	p := policyArcProfile()
	cert := createCertWithPolicies(t, "2.23.140.1.2.1", "1.2.3.4.5")

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-016" && f.Severity == Error && strings.Contains(f.Message, "1.2.3.4.5") {
			found = true
		}
	}
	if !found {
		t.Error("a policy outside every permitted arc should be reported")
	}
}

// TestLintPolicyArcRespectsComponentBoundary guards against prefix matching on
// raw text: 1.3.6.1.4.1.64499 is not under the 1.3.6.1.4.1.6449 arc.
func TestLintPolicyArcRespectsComponentBoundary(t *testing.T) {
	p := policyArcProfile()
	cert := createCertWithPolicies(t, "2.23.140.1.2.1", "1.3.6.1.4.1.64499.1")

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-016" && f.Severity == Error && strings.Contains(f.Message, "64499") {
			found = true
		}
	}
	if !found {
		t.Error("an OID sharing only a text prefix with the arc should be reported")
	}
}

// ---------- Precertificates vs final certificates ----------

// ctProfile describes both kinds of certificate, as a CT-logging profile must.
func ctProfile() profile.Profile {
	ca := false
	return profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: fixtureSubject(),
			Extensions: map[string]profile.Extension{
				"signed_certificate_timestamps": {Required: profile.PresenceFinalOnly},
				"precertificate_poison": {
					Required: profile.PresencePrecertificateOnly,
					Critical: profile.CriticalityRequired,
				},
				"basic_constraints": {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, CA: &ca},
			},
		},
	}
}

// certWithCTExtensions builds a parsed certificate carrying the requested
// Certificate Transparency extensions.
func certWithCTExtensions(t *testing.T, poison, sct bool) *x509.Certificate {
	t.Helper()

	var extra []pkix.Extension
	if poison {
		extra = append(extra, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
			Critical: true,
			Value:    []byte{0x05, 0x00}, // ASN.1 NULL
		})
	}
	if sct {
		extra = append(extra, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
			Value: []byte{0x04, 0x02, 0x00, 0x00},
		})
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions:       extra,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// TestIsPrecertificateDetection verifies the poison extension identifies a
// Precertificate.
func TestIsPrecertificateDetection(t *testing.T) {
	if !isPrecertificate(certWithCTExtensions(t, true, false)) {
		t.Error("a certificate with the poison extension is a Precertificate")
	}
	if isPrecertificate(certWithCTExtensions(t, false, true)) {
		t.Error("a certificate with SCTs and no poison is a final certificate")
	}
}

// TestLintPrecertificateAccepted verifies a well-formed Precertificate passes:
// poison present, no SCTs.
func TestLintPrecertificateAccepted(t *testing.T) {
	cert := certWithCTExtensions(t, true, false)

	for _, f := range lint(cert, ctProfile()) {
		if f.Severity == Error {
			t.Errorf("a well-formed Precertificate must not error, got: %s", f)
		}
	}
}

// TestLintFinalCertificateAccepted verifies a well-formed final certificate
// passes: SCTs present, no poison.
func TestLintFinalCertificateAccepted(t *testing.T) {
	cert := certWithCTExtensions(t, false, true)

	for _, f := range lint(cert, ctProfile()) {
		if f.Severity == Error {
			t.Errorf("a well-formed final certificate must not error, got: %s", f)
		}
	}
}

// TestLintPrecertificateWithSCTsRejected verifies SCTs are forbidden in a
// Precertificate.
func TestLintPrecertificateWithSCTsRejected(t *testing.T) {
	cert := certWithCTExtensions(t, true, true)

	found := false
	for _, f := range lint(cert, ctProfile()) {
		if f.RuleID == "EXT-017" && f.Severity == Error &&
			strings.Contains(f.Message, "signed_certificate_timestamps") {
			found = true
		}
	}
	if !found {
		t.Error("SCTs in a Precertificate should be reported")
	}
}

// TestLintFinalCertificateMissingSCTsRejected verifies SCTs are required in a
// final certificate.
func TestLintFinalCertificateMissingSCTsRejected(t *testing.T) {
	cert := certWithCTExtensions(t, false, false)

	found := false
	for _, f := range lint(cert, ctProfile()) {
		if f.RuleID == "EXT-011" && f.Severity == Error &&
			strings.Contains(f.Message, "signed_certificate_timestamps") {
			found = true
		}
	}
	if !found {
		t.Error("a final certificate without SCTs should be reported")
	}
}

// TestLintFinalCertificateWithPoisonRejected verifies that a certificate
// carrying poison is judged as a Precertificate, so its missing SCTs are not
// reported but its poison is accepted.
func TestLintPoisonMakesItAPrecertificate(t *testing.T) {
	cert := certWithCTExtensions(t, true, false)

	for _, f := range lint(cert, ctProfile()) {
		if f.RuleID == "EXT-011" && strings.Contains(f.Message, "signed_certificate_timestamps") {
			t.Errorf("a Precertificate must not be required to carry SCTs, got: %s", f)
		}
	}
}

// TestLintPrecertificateWarnsWhenProfileSilent verifies a profile that does not
// describe Precertificates says so rather than silently mis-linting.
func TestLintPrecertificateWarnsWhenProfileSilent(t *testing.T) {
	ca := false
	p := profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"basic_constraints": {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, CA: &ca},
			},
		},
	}

	cert := certWithCTExtensions(t, true, false)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "CT-001" && f.Severity == Warning {
			found = true
		}
	}
	if !found {
		t.Error("a profile silent about Precertificates should produce a warning")
	}
}

// ---------- Alternative name types ----------

// sanProfile permits only the given general name types.
func sanProfile(required, optional []string) profile.Profile {
	ca := false
	return profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: fixtureSubject(),
			Extensions: map[string]profile.Extension{
				"subject_alt_name": {
					Required:       profile.PresenceRequired,
					Critical:       profile.CriticalityOptional,
					RequiredValues: required,
					OptionalValues: optional,
				},
				"basic_constraints": {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, CA: &ca},
			},
		},
	}
}

// certWithSANs builds a parsed certificate with the requested SAN entries.
func certWithSANs(t *testing.T, dnsNames, emails []string, ips []net.IP) *x509.Certificate {
	t.Helper()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		EmailAddresses:        emails,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// TestLintGeneralNameTypesAccepted verifies listed name types pass.
func TestLintGeneralNameTypesAccepted(t *testing.T) {
	p := sanProfile(nil, []string{"dns_name", "ip_address"})
	cert := certWithSANs(t, []string{"example.com"}, nil, []net.IP{net.ParseIP("192.0.2.1")})

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("listed name types must not error, got: %s", f)
		}
	}
}

// TestLintGeneralNameTypeNotListed verifies an unlisted name type is reported.
func TestLintGeneralNameTypeNotListed(t *testing.T) {
	p := sanProfile(nil, []string{"dns_name", "ip_address"})
	cert := certWithSANs(t, []string{"example.com"}, []string{"admin@example.com"}, nil)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-019" && f.Severity == Error && strings.Contains(f.Message, "rfc822Name") {
			found = true
		}
	}
	if !found {
		t.Error("an unlisted general name type should be reported")
	}
}

// TestLintGeneralNameTypeRequiredMissing verifies a required name type that is
// absent is reported.
func TestLintGeneralNameTypeRequiredMissing(t *testing.T) {
	p := sanProfile([]string{"dns_name"}, []string{"ip_address"})
	cert := certWithSANs(t, nil, nil, []net.IP{net.ParseIP("192.0.2.1")})

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-018" && f.Severity == Error && strings.Contains(f.Message, "dNSName") {
			found = true
		}
	}
	if !found {
		t.Error("a missing required general name type should be reported")
	}
}

// TestLintGeneralNameAliasesResolve verifies alias spellings behave identically.
func TestLintGeneralNameAliasesResolve(t *testing.T) {
	p := sanProfile(nil, []string{"dns", "ip"})
	cert := certWithSANs(t, []string{"example.com"}, nil, []net.IP{net.ParseIP("192.0.2.1")})

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("alias name types must be accepted, got: %s", f)
		}
	}
}

// ---------- CRL distribution points ----------

// crldpProfile permits distribution points of the given shape.
func crldpProfile(dps ...profile.DistributionPoint) profile.Profile {
	ca := false
	return profile.Profile{
		Profile: profile.Meta{Name: "Test Profile", Version: 3},
		Requirements: profile.Requirements{
			Subject: fixtureSubject(),
			Extensions: map[string]profile.Extension{
				"crl_distribution_points": {
					Required:           profile.PresenceRequired,
					DistributionPoints: dps,
				},
				"basic_constraints": {Required: profile.PresenceRequired, Critical: profile.CriticalityRequired, CA: &ca},
			},
		},
	}
}

// certWithCRLDP builds a parsed certificate whose CRL distribution points
// extension is assembled from the supplied DER bodies.
func certWithCRLDP(t *testing.T, dpBodies ...[]byte) *x509.Certificate {
	t.Helper()

	var seqBody []byte
	for _, body := range dpBodies {
		dp, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      body,
		})
		if err != nil {
			t.Fatalf("marshalling distribution point: %v", err)
		}
		seqBody = append(seqBody, dp...)
	}

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqBody,
	})
	if err != nil {
		t.Fatalf("marshalling distribution points: %v", err)
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: value},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// ctx wraps body in a context-specific tag.
func ctx(t *testing.T, tag int, compound bool, body []byte) []byte {
	t.Helper()
	out, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: compound,
		Bytes:      body,
	})
	if err != nil {
		t.Fatalf("marshalling context tag %d: %v", tag, err)
	}
	return out
}

// fullNameDP builds a DistributionPoint body with a fullName holding one name
// of each supplied tag.
func fullNameDP(t *testing.T, tags ...int) []byte {
	t.Helper()
	var names []byte
	for _, tag := range tags {
		names = append(names, ctx(t, tag, false, []byte("http://crl.example.com/ca.crl"))...)
	}
	return ctx(t, 0, true, ctx(t, 0, true, names))
}

// TestLintCRLDistributionPointAccepted verifies a URI distribution point passes.
func TestLintCRLDistributionPointAccepted(t *testing.T) {
	p := crldpProfile(profile.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
		Required: true,
	})
	cert := certWithCRLDP(t, fullNameDP(t, 6))

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("a URI distribution point must not error, got: %s", f)
		}
	}
}

// TestLintCRLDistributionPointUnlistedNameType verifies a name type outside the
// profile is reported.
func TestLintCRLDistributionPointUnlistedNameType(t *testing.T) {
	p := crldpProfile(profile.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
	})
	// Tag 4 is directoryName, which the profile does not permit.
	cert := certWithCRLDP(t, fullNameDP(t, 6, 4))

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-021" && f.Severity == Error && strings.Contains(f.Message, "directoryName") {
			found = true
		}
	}
	if !found {
		t.Error("a name type not listed in the profile should be reported")
	}
}

// TestLintCRLDistributionPointUndeclaredReasons verifies the optional reasons
// field is reported when the profile does not describe it.
func TestLintCRLDistributionPointUndeclaredReasons(t *testing.T) {
	p := crldpProfile(profile.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
	})

	body := append(fullNameDP(t, 6), ctx(t, 1, false, []byte{0x01, 0x02})...)
	cert := certWithCRLDP(t, body)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-021" && f.Severity == Error && strings.Contains(f.Message, "reasons") {
			found = true
		}
	}
	if !found {
		t.Error("an undeclared reasons field should be reported")
	}
}

// TestLintCRLDistributionPointDeclaredReasons verifies it passes once declared.
func TestLintCRLDistributionPointDeclaredReasons(t *testing.T) {
	p := crldpProfile(profile.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
		Reasons:  true,
	})

	body := append(fullNameDP(t, 6), ctx(t, 1, false, []byte{0x01, 0x02})...)
	cert := certWithCRLDP(t, body)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-021" {
			t.Errorf("a declared reasons field must not be reported, got: %s", f)
		}
	}
}

// TestProfileValidationError tests that ValidateProfile rejects invalid profiles.
// This is tested by calling ValidateProfile directly, not by running main.
func TestProfileValidationError(t *testing.T) {
	invalidProfile := &profile.Profile{
		Profile: profile.Meta{Name: "Invalid Profile", Version: 3},
		Requirements: profile.Requirements{
			Extensions: map[string]profile.Extension{
				"made_up_extension": {Critical: profile.CriticalityForbidden},
			},
		},
	}

	errs := profile.ValidateProfile(invalidProfile)
	if len(errs) == 0 {
		t.Fatal("ValidateProfile should detect unknown extension")
	}

	found := false
	for _, err := range errs {
		if strings.Contains(err, "made_up_extension") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("error should mention made_up_extension, got: %v", errs)
	}
}

// TestFinding tests the Finding string representation.
func TestFinding(t *testing.T) {
	tests := []struct {
		finding Finding
		want    string
	}{
		{
			Finding{RuleID: "TEST-001", Severity: Error, Message: "Test error"},
			"[ERROR] TEST-001: Test error",
		},
		{
			Finding{Severity: Warning, Message: "Test warning"},
			"[WARNING] Test warning",
		},
		{
			Finding{Severity: Info, Message: "Test info"},
			"[INFO] Test info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.finding.String()
			if got != tt.want {
				t.Errorf("Finding.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSubjectValues tests the subjectValues helper function.
func TestSubjectValues(t *testing.T) {
	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	values := subjectValues(cert)

	// Keys are the canonical snake_case form of the X.520 attribute names.
	want := map[string]string{
		"common_name":       "example.com",
		"organization_name": "Test Org",
		"country_name":      "US",
	}

	for key, expected := range want {
		got := values[key]
		if len(got) == 0 {
			t.Errorf("%s should be present, got no values", key)
			continue
		}
		if got[0] != expected {
			t.Errorf("%s should be %q, got %q", key, expected, got[0])
		}
	}
}

// TestSubjectValuesCoversUnstructuredAttributes verifies attributes outside the
// structured pkix.Name fields are still resolved, which is what allows a
// profile to constrain things like business category.
func TestSubjectValuesCoversUnstructuredAttributes(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.com",
			ExtraNames: []pkix.AttributeTypeAndValue{
				// businessCategory
				{Type: asn1.ObjectIdentifier{2, 5, 4, 15}, Value: "Private Organization"},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	values := subjectValues(cert)

	got := values["business_category"]
	if len(got) == 0 || got[0] != "Private Organization" {
		t.Errorf("business_category should be resolved from the DN, got %v", got)
	}
}
