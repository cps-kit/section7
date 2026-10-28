package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/cps-kit/section7"
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
func createEmptySubjectCert(t *testing.T, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

// TestLintValidCertificate tests linting a certificate that meets all requirements.
func TestLintValidCertificate(t *testing.T) {
	ca := false
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: section7.SignatureAlgorithm{
				Allowed: []string{"sha256WithRSAEncryption"},
			},
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "rsaEncryption", KeySizes: []int{2048}}},
			},
			Validity: section7.Validity{MaximumDays: 365},
			Issuer: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
			Extensions: map[string]section7.Extension{
				"basic_constraints":  {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
				"key_usage":          {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, RequiredValues: []string{"digitalSignature"}},
				"extended_key_usage": {Required: section7.PresenceRequired, RequiredValues: []string{"serverAuth"}},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	findings := section7.Lint(cert, p)

	// Should have some info findings
	errors := 0
	for _, f := range findings {
		if f.Severity == section7.Error {
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("Valid certificate should not have errors, got %d", errors)
		for _, f := range findings {
			if f.Severity == section7.Error {
				t.Logf("  section7.Error: %s", f)
			}
		}
	}
}

// TestLintValidityViolation tests detection of validity period violation.
func TestLintValidityViolation(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Validity: section7.Validity{MaximumDays: 10}, // Very short
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil) // 30 day cert

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "validity") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"locality": {Required: true}, // Not in our test cert
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "locality") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"organization_name": {Required: true, Length: section7.FieldLength{Max: &maxLen}},
				},
			},
		},
	}

	cert, _ := createTestCert("example.com", "This is a very long org name", "US", 30, false, nil)

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "exceeds maximum length") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"organization_name": {Required: true, Length: section7.FieldLength{Max: &maxLen}},
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

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-003" {
			t.Errorf("a 64-character value must not violate a 64-character limit, got: %s", f)
		}
	}
}

// TestLintSubjectLengthTooLongInCharacters verifies the limit is still enforced
// when the value genuinely exceeds it in characters.
func TestLintSubjectLengthTooLongInCharacters(t *testing.T) {
	maxLen := 5
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"organization_name": {Required: true, Length: section7.FieldLength{Max: &maxLen}},
				},
			},
		},
	}

	// 6 characters (12 bytes) against a 5-character limit.
	cert, _ := createTestCert("example.com", "ééééék", "US", 30, false, nil)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-003" && f.Severity == section7.Error {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"organization_name": {Required: true, Length: section7.FieldLength{Min: &minLen}},
				},
			},
		},
	}

	// 2 characters but 6 bytes: must still fail a 3-character minimum.
	cert, _ := createTestCert("example.com", "éé", "US", 30, false, nil)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-002" && f.Severity == section7.Error {
			found = true
		}
	}
	if !found {
		t.Error("a 2-character value should fail a 3-character minimum despite being 6 bytes")
	}
}

// hasFinding reports whether a finding with the given rule ID and severity exists.
func hasFinding(findings []section7.Finding, ruleID string, sev section7.Severity) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Severity == sev {
			return true
		}
	}
	return false
}

// sanExtension builds a subjectAltName extension carrying one dNSName. Go
// would otherwise always mark it critical for an empty subject.
func sanExtension(t *testing.T, critical bool) pkix.Extension {
	t.Helper()

	der, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("example.com")},
	})
	if err != nil {
		t.Fatalf("encoding subjectAltName: %v", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: critical, Value: der}
}

// TestLintEmptySubjectRejectedWhenAttributeRequired verifies a required
// attribute makes an empty subject non-conforming.
func TestLintEmptySubjectRejectedWhenAttributeRequired(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"organization_name": {Required: true},
				},
			},
		},
	}

	cert := createEmptySubjectCert(t, sanExtension(t, true))

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-001" && f.Severity == section7.Error &&
			strings.Contains(f.Message, "'organizationName'") {
			found = true
		}
	}
	if !found {
		t.Error("an empty subject must be reported as missing its required attributes")
	}
}

// TestLintEmptySubjectRequiresCriticalSAN verifies the RFC 5280 rule that an
// empty subject must be accompanied by a critical subjectAltName, and that it
// then conforms when no attribute is required.
func TestLintEmptySubjectRequiresCriticalSAN(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name": {Required: false},
				},
			},
		},
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		want     section7.Severity
		inMsg    string
		conforms bool
	}{
		{"no SAN", createEmptySubjectCert(t), section7.Error, "is required", false},
		{"non-critical SAN", createEmptySubjectCert(t, sanExtension(t, false)), section7.Error, "must be critical", false},
		{"critical SAN", createEmptySubjectCert(t, sanExtension(t, true)), section7.Info, "OK", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, f := range section7.Lint(tt.cert, p) {
				if f.RuleID == "SUBJECT-005" && f.Severity == tt.want && strings.Contains(f.Message, tt.inMsg) {
					found = true
				}
				if tt.conforms && strings.HasPrefix(f.RuleID, "SUBJECT-") && f.Severity == section7.Error {
					t.Errorf("an empty subject with no required attributes should conform, got: %s", f)
				}
			}
			if !found {
				t.Errorf("expected SUBJECT-005 %v containing %q", tt.want, tt.inMsg)
			}
		})
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-005" {
			t.Errorf("the empty-subject SAN rule must not apply to a populated subject, got: %s", f)
		}
	}
}

// TestLintCAViolation tests detection of CA constraint violation.
func TestLintCAViolation(t *testing.T) {
	ca := false
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Critical: section7.CriticalityRequired, CA: &ca},
			},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, true, nil) // isCA=true

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "CA=") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"extended_key_usage": {
					Critical:       section7.CriticalityForbidden,
					RequiredValues: []string{"clientAuth"},
				},
			},
		},
	}

	// Create cert without clientAuth
	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "clientAuth") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"key_usage": {
					Critical:       section7.CriticalityRequired,
					RequiredValues: []string{"keyCertSign"},
				},
			},
		},
	}

	// Create cert with default key usage (no keyCertSign)
	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	findings := section7.Lint(cert, p)

	found := false
	for _, f := range findings {
		if f.Severity == section7.Error && strings.Contains(f.Message, "keyCertSign") {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name": {Required: true},
					// organization_name and country are deliberately omitted.
				},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	findings := section7.Lint(cert, p)

	var unlisted []string
	for _, f := range findings {
		if f.RuleID == "SUBJECT-004" && f.Severity == section7.Error {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-004" {
			t.Errorf("listed attributes must not be reported, got: %s", f)
		}
	}
}

// TestLintProfileWithoutSubjectPermitsNoAttributes verifies that saying nothing
// about the subject is the strict answer, not the permissive one: a profile
// with no subject block permits no subject attributes.
func TestLintProfileWithoutSubjectPermitsNoAttributes(t *testing.T) {
	p := section7.Profile{
		Profile:      section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	var unlisted []string
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "SUBJECT-004" && f.Severity == section7.Error {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Critical: section7.CriticalityRequired, CA: &ca},
				// key_usage and extended_key_usage deliberately omitted.
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	var unlisted []string
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-009" && f.Severity == section7.Error {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"basic_constraints":  {Critical: section7.CriticalityRequired, CA: &ca},
				"key_usage":          {RequiredValues: []string{"digitalSignature"}},
				"extended_key_usage": {RequiredValues: []string{"serverAuth"}},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-009" {
			t.Errorf("listed extensions must not be reported, got: %s", f)
		}
	}
}

// TestLintProfileWithoutExtensionsPermitsNone verifies that a profile with no
// extensions block permits no extensions, rather than permitting every one.
func TestLintProfileWithoutExtensionsPermitsNone(t *testing.T) {
	p := section7.Profile{
		Profile:      section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	var unlisted []string
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-009" && f.Severity == section7.Error {
			unlisted = append(unlisted, f.Message)
		}
	}
	if len(unlisted) != len(cert.Extensions) {
		t.Fatalf("every extension in the certificate should be reported, got: %v", unlisted)
	}
}

// TestLintExtensionAcceptedByOID verifies an extension may be listed by raw OID.
func TestLintExtensionAcceptedByOID(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"2.5.29.19": {Critical: section7.CriticalityRequired}, // basic constraints, by OID
				"2.5.29.15": {},                                       // key usage, by OID
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-009" {
			t.Errorf("extensions listed by OID must be accepted, got: %s", f)
		}
	}
}

// ---------- Version, signature algorithm and public key ----------

// createECCert builds a parsed certificate with an elliptic curve key.
func createECCert(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// TestLintVersionMismatch verifies the certificate version is checked against
// the version the profile describes.
func TestLintVersionMismatch(t *testing.T) {
	p := section7.Profile{
		Profile:      section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{Version: 1},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	if !hasFinding(lint(cert, p), "VERSION-001", Error) {
		t.Error("a v3 certificate should not satisfy a profile describing v1")
	}
}

// TestLintSignatureAlgorithmNotListed verifies an algorithm outside the
// profile's list is reported.
func TestLintSignatureAlgorithmNotListed(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: section7.SignatureAlgorithm{Allowed: []string{"ecdsa-with-SHA256"}},
		},
	}

	// createParsedTestCert signs with SHA-256 and RSA.
	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	if !hasFinding(lint(cert, p), "SIGALG-001", Error) {
		t.Error("an RSA signature should not satisfy an ECDSA-only profile")
	}
}

// TestLintSignatureAlgorithmListed verifies the permitted algorithm passes.
func TestLintSignatureAlgorithmListed(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: section7.SignatureAlgorithm{Allowed: []string{"sha256WithRSAEncryption"}},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	findings := lint(cert, p)
	if hasFinding(findings, "SIGALG-001", Error) {
		t.Errorf("a permitted signature algorithm must not be reported, got: %v", findings)
	}
}

// TestSignatureAlgorithmIdentifiersMustMatch records why the linter does not
// check that the outer signatureAlgorithm matches the signature field inside
// the TBSCertificate: crypto/x509 refuses to parse such a certificate, so one
// can never reach the linter. If that ever changes, the profile states the
// requirement and this test will say so.
func TestSignatureAlgorithmIdentifiersMustMatch(t *testing.T) {
	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	// AlgorithmIdentifier for sha256WithRSAEncryption. The OID for
	// sha384WithRSAEncryption differs only in its final byte, so rewriting the
	// outer copy keeps every length in the encoding intact.
	sha256RSA := []byte{
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
	}
	tampered := bytes.Clone(cert.Raw)
	last := bytes.LastIndex(tampered, sha256RSA)
	if last == -1 || bytes.Index(tampered, sha256RSA) == last {
		t.Fatal("the fixture should carry the algorithm identifier twice")
	}
	tampered[last+12] = 0x0c

	if _, err := x509.ParseCertificate(tampered); err == nil {
		t.Fatal("disagreeing signature algorithm identifiers should not parse; the linter must check this itself")
	}
}

// TestLintPublicKeyAlgorithmNotListed verifies a key algorithm outside the
// profile's list is reported.
func TestLintPublicKeyAlgorithmNotListed(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "id-ecPublicKey", Curves: []string{"P-256"}}},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	if !hasFinding(lint(cert, p), "PUBKEY-001", Error) {
		t.Error("an RSA key should not satisfy an elliptic curve only profile")
	}
}

// TestLintPublicKeySizeNotListed verifies a key size outside the profile's
// list is reported.
func TestLintPublicKeySizeNotListed(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "rsaEncryption", KeySizes: []int{4096}}},
			},
		},
	}

	// createParsedTestCert uses a 2048 bit key.
	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	if !hasFinding(lint(cert, p), "PUBKEY-002", Error) {
		t.Error("a 2048 bit key should not satisfy a 4096 bit only profile")
	}
}

// TestLintPublicKeyCurve verifies curves are matched, including through an
// alias spelling.
func TestLintPublicKeyCurve(t *testing.T) {
	permitted := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "id-ecPublicKey", Curves: []string{"secp256r1"}}},
			},
		},
	}
	forbidden := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			PublicKey: section7.PublicKey{
				Algorithms: []section7.KeyAlgorithm{{Name: "id-ecPublicKey", Curves: []string{"P-384"}}},
			},
		},
	}

	cert := createECCert(t, elliptic.P256())

	if hasFinding(lint(cert, permitted), "PUBKEY-003", Error) {
		t.Error("an alias spelling of the certificate's curve should be accepted")
	}
	if !hasFinding(lint(cert, forbidden), "PUBKEY-003", Error) {
		t.Error("a curve outside the profile's list should be reported")
	}
}

// TestLintIssuerAttributesChecked verifies the issuer is held to the same
// exhaustive attribute list as the subject.
func TestLintIssuerAttributesChecked(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Issuer: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"locality":          {Required: true}, // not present in the fixture
					"organization_name": {},
				},
			},
		},
	}

	// The fixture is self-signed, so its issuer carries commonName,
	// organizationName and countryName.
	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)
	findings := lint(cert, p)

	if !hasFinding(findings, "ISSUER-001", Error) {
		t.Error("a missing required issuer attribute should be reported")
	}

	var unlisted []string
	for _, f := range findings {
		if f.RuleID == "ISSUER-004" && f.Severity == Error {
			unlisted = append(unlisted, f.Message)
		}
	}
	if len(unlisted) != 1 || !strings.Contains(unlisted[0], "countryName") {
		t.Errorf("countryName should be reported as unlisted in the issuer, got: %v", unlisted)
	}
}

// TestLintEmptyIssuerRejected verifies the RFC 5280 rule that the issuer is
// never empty, whatever the profile says.
func TestLintEmptyIssuerRejected(t *testing.T) {
	p := section7.Profile{Profile: section7.Meta{Name: "Test Profile"}}

	// Self-signed with an empty subject, so the issuer is empty too.
	if !hasFinding(lint(createEmptySubjectCert(t), p), "ISSUER-000", Error) {
		t.Error("an empty issuer should be reported")
	}
	if hasFinding(lint(createParsedTestCert(t, "example.com", "Test Org", "US", nil), p), "ISSUER-000", Error) {
		t.Error("a populated issuer must not be reported as empty")
	}
}

// TestLintProfileWithoutAlgorithmsPermitsNone verifies that an unstated
// algorithm list is the strict answer, as it is for extensions and attributes:
// a certificate is signed with some algorithm and carries some key, and a
// profile that names neither describes no certificate at all.
func TestLintProfileWithoutAlgorithmsPermitsNone(t *testing.T) {
	p := section7.Profile{
		Profile:      section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)
	findings := lint(cert, p)

	if !hasFinding(findings, "SIGALG-001", Error) {
		t.Error("a profile listing no signature algorithms must permit none")
	}
	if !hasFinding(findings, "PUBKEY-001", Error) {
		t.Error("a profile listing no public key algorithms must permit none")
	}
}

// ---------- Serial number ----------

func TestLintSerialNumberRequiredOK(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SerialNumber: section7.SerialNumber{Required: true, Declared: true},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)

	if !hasFinding(section7.Lint(cert, p), "SERIAL-001", section7.Info) {
		t.Error("a positive serial number should satisfy the requirement")
	}
}

func TestLintSerialNumberZeroRejected(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SerialNumber: section7.SerialNumber{Required: true, Declared: true},
		},
	}

	cert, _ := createTestCert("example.com", "Test Org", "US", 30, false, nil)
	cert.SerialNumber = big.NewInt(0)

	if !hasFinding(section7.Lint(cert, p), "SERIAL-001", section7.Error) {
		t.Error("a zero serial number should be rejected")
	}
}

// ---------- Criticality ----------

// TestLintCriticalityCheckedForAllExtensions guards against the criticality
// check only covering a hard-coded set of extensions. Go emits Subject Key
// Identifier as non-critical, so a profile demanding critical=true must fail.
func TestLintCriticalityCheckedForAllExtensions(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"subject_key_identifier": {Critical: section7.CriticalityRequired},
			},
		},
	}

	cert := createCertWithSKI(t)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == section7.Error &&
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"subject_key_identifier": {Critical: section7.CriticalityForbidden},
			},
		},
	}

	cert := createCertWithSKI(t)

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == section7.Error {
			t.Errorf("a matching criticality must not be reported, got: %s", f)
		}
	}
}

// TestLintCriticalityCheckedForOIDKeyedExtension verifies the check also works
// when the extension is listed by raw OID.
func TestLintCriticalityCheckedForOIDKeyedExtension(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"2.5.29.14": {Critical: section7.CriticalityRequired}, // subject key identifier, by OID
			},
		},
	}

	cert := createCertWithSKI(t)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == section7.Error {
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
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"name_constraints": {Critical: section7.CriticalityRequired}, // not present in the test cert
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	found := false
	for _, f := range section7.Lint(cert, p) {
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

// ---------- Extension presence (required: true/false) ----------

// TestLintRequiredExtensionMissing verifies required: true is enforced.
func TestLintRequiredExtensionMissing(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				// Absent from the test certificate.
				"subject_key_identifier": {Required: section7.PresenceRequired},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-011" && f.Severity == Error &&
			strings.Contains(f.Message, "subject_key_identifier") {
			found = true
		}
	}
	if !found {
		t.Error("a missing extension marked required: true must be reported as an error")
	}
}

// TestLintOptionalExtensionMissing verifies required: false is not an error.
func TestLintOptionalExtensionMissing(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"subject_key_identifier": {Required: section7.PresenceOptional},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-011" {
			t.Errorf("an absent extension marked required: false must not error, got: %s", f)
		}
	}
	if !hasFinding(lint(cert, p), "EXT-010", Info) {
		t.Error("an absent optional extension should still be reported as permitted-but-absent")
	}
}

// TestLintRequiredExtensionPresent verifies no error when a required extension
// is in fact present.
func TestLintRequiredExtensionPresent(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"subject_key_identifier": {Required: section7.PresenceRequired, Critical: section7.CriticalityForbidden},
			},
		},
	}

	cert := createCertWithSKI(t)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-011" {
			t.Errorf("a present required extension must not be reported, got: %s", f)
		}
	}
}

// ---------- Access descriptions (AIA) ----------

// aiaProfile builds a profile requiring the given access methods. It also
// lists the other extensions the fixture certificate carries, so that
// assertions can look at all errors rather than only AIA rules.
func aiaProfile(descriptions ...section7.AccessDescription) section7.Profile {
	ca := false
	return section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: fixtureSignature(),
			PublicKey:          fixtureKey(),
			Issuer:             fixtureDN(),
			Subject:            fixtureDN(),
			Extensions: map[string]section7.Extension{
				"authority_information_access": {
					Required:           section7.PresenceRequired,
					Critical:           section7.CriticalityForbidden,
					AccessDescriptions: descriptions,
				},
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
				"key_usage":         {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, RequiredValues: []string{"digitalSignature"}},
			},
		},
	}
}

// TestLintAccessDescriptionsPresent verifies both listed methods are accepted.
func TestLintAccessDescriptionsPresent(t *testing.T) {
	p := aiaProfile(
		section7.AccessDescription{AccessMethod: "id-ad-caIssuers", Required: true},
		section7.AccessDescription{AccessMethod: "id-ad-ocsp", Required: true},
	)

	cert := createCertWithAIA(t,
		[]string{"http://ocsp.example.com"},
		[]string{"http://crt.example.com/ca.crt"})

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("a certificate with both access methods must not error, got: %s", f)
		}
	}
}

// TestLintAccessDescriptionMissingRequired verifies a required access method
// that is absent is reported.
func TestLintAccessDescriptionMissingRequired(t *testing.T) {
	p := aiaProfile(
		section7.AccessDescription{AccessMethod: "id-ad-caIssuers", Required: true},
		section7.AccessDescription{AccessMethod: "id-ad-ocsp", Required: true},
	)

	// Only caIssuers present.
	cert := createCertWithAIA(t, nil, []string{"http://crt.example.com/ca.crt"})

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-012" && f.Severity == Error && strings.Contains(f.Message, "id-ad-ocsp") {
			found = true
		}
	}
	if !found {
		t.Error("a missing required access method should be reported")
	}
}

// TestLintAccessDescriptionNotListed verifies an access method present in the
// certificate but absent from the profile is reported.
func TestLintAccessDescriptionNotListed(t *testing.T) {
	// Profile permits only caIssuers.
	p := aiaProfile(section7.AccessDescription{AccessMethod: "id-ad-caIssuers", Required: true})

	cert := createCertWithAIA(t,
		[]string{"http://ocsp.example.com"},
		[]string{"http://crt.example.com/ca.crt"})

	found := false
	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-013" && f.Severity == Error && strings.Contains(f.Message, "id-ad-ocsp") {
			found = true
		}
	}
	if !found {
		t.Error("an access method not listed in the profile should be reported")
	}
}

// TestLintAccessDescriptionOptionalAbsent verifies an optional access method
// that is absent is not an error.
func TestLintAccessDescriptionOptionalAbsent(t *testing.T) {
	p := aiaProfile(
		section7.AccessDescription{AccessMethod: "id-ad-caIssuers", Required: true},
		section7.AccessDescription{AccessMethod: "id-ad-ocsp", Required: false},
	)

	cert := createCertWithAIA(t, nil, []string{"http://crt.example.com/ca.crt"})

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("an absent optional access method must not error, got: %s", f)
		}
	}
}

// TestLintAccessDescriptionsByOID verifies access methods may be listed by OID.
func TestLintAccessDescriptionsByOID(t *testing.T) {
	p := aiaProfile(
		section7.AccessDescription{AccessMethod: "1.3.6.1.5.5.7.48.2", Required: true},
		section7.AccessDescription{AccessMethod: "1.3.6.1.5.5.7.48.1", Required: true},
	)

	cert := createCertWithAIA(t,
		[]string{"http://ocsp.example.com"},
		[]string{"http://crt.example.com/ca.crt"})

	for _, f := range lint(cert, p) {
		if f.Severity == Error {
			t.Errorf("access methods listed by OID must be accepted, got: %s", f)
		}
	}
}

// TestLintFindingsFollowCertificateOrder verifies findings are reported in the
// field order of the TBSCertificate, so a report reads alongside a certificate.
func TestLintFindingsFollowCertificateOrder(t *testing.T) {
	ca := false
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Version:            3,
			SerialNumber:       section7.SerialNumber{Required: true},
			SignatureAlgorithm: fixtureSignature(),
			Issuer:             fixtureDN(),
			Validity:           section7.Validity{MaximumDays: 398},
			Subject:            fixtureDN(),
			PublicKey:          fixtureKey(),
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
			},
		},
	}

	first := map[string]int{}
	for i, f := range lint(createCertWithSKI(t), p) {
		prefix, _, _ := strings.Cut(f.RuleID, "-")
		if _, seen := first[prefix]; !seen {
			first[prefix] = i
		}
	}

	order := []string{"VERSION", "SERIAL", "SIGALG", "ISSUER", "VALIDITY", "SUBJECT", "PUBKEY", "EXT"}
	for i := 1; i < len(order); i++ {
		prev, okPrev := first[order[i-1]]
		cur, ok := first[order[i]]
		if !okPrev || !ok || cur < prev {
			t.Fatalf("findings should follow %v, got first positions %v", order, first)
		}
	}
}

// TestLintFindingOrderIsStable guards against iterating the profile's maps
// directly. Go randomizes map iteration, so doing that made the findings for
// one certificate come out in a different order on every run.
func TestLintFindingOrderIsStable(t *testing.T) {
	p := aiaProfile(
		section7.AccessDescription{AccessMethod: "id-ad-caIssuers", Required: true},
		section7.AccessDescription{AccessMethod: "id-ad-ocsp", Required: true},
	)
	p.Requirements.Subject = section7.DistinguishedName{
		Attributes: map[string]section7.Field{
			"common_name":            {},
			"country_name":           {},
			"organization_name":      {},
			"state_or_province_name": {},
			"locality_name":          {},
		},
	}

	cert := createCertWithAIA(t,
		[]string{"http://ocsp.example.com"},
		[]string{"http://crt.example.com/ca.crt"})

	first := lint(cert, p)
	for i := 0; i < 20; i++ {
		next := lint(cert, p)
		if len(next) != len(first) {
			t.Fatalf("finding count changed between runs: %d then %d", len(first), len(next))
		}
		for j := range first {
			if next[j].RuleID != first[j].RuleID || next[j].Message != first[j].Message {
				t.Fatalf("finding %d differs between runs:\n  %s\n  %s", j, first[j], next[j])
			}
		}
	}
}

// TestSubjectAttributesFollowEncodingOrder verifies the attribute findings are
// reported in the order a conforming certificate encodes them, as required by
// Section 7.1.4.2 of the Baseline Requirements.
func TestSubjectAttributesFollowEncodingOrder(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Subject: section7.DistinguishedName{
				Attributes: map[string]section7.Field{
					"common_name":       {Required: true},
					"country_name":      {Required: true},
					"organization_name": {Required: true},
				},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	var order []string
	for _, f := range lint(cert, p) {
		if !strings.HasPrefix(f.RuleID, "SUBJECT-") {
			continue
		}
		switch {
		case strings.Contains(f.Message, "'countryName'"):
			order = append(order, "countryName")
		case strings.Contains(f.Message, "'organizationName'"):
			order = append(order, "organizationName")
		case strings.Contains(f.Message, "'commonName'"):
			order = append(order, "commonName")
		}
	}

	want := []string{"countryName", "organizationName", "commonName"}
	if len(order) != len(want) {
		t.Fatalf("expected one finding per attribute, got %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("attributes reported as %v, want %v", order, want)
		}
	}
}

// TestLintCriticalityOptionalAcceptsNonCritical verifies `critical: optional`
// accepts a non-critical extension.
func TestLintCriticalityOptionalAcceptsNonCritical(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"subject_key_identifier": {Critical: section7.CriticalityOptional},
			},
		},
	}

	// Go emits Subject Key Identifier as non-critical.
	cert := createCertWithSKI(t)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == Error {
			t.Errorf("critical: optional must accept a non-critical extension, got: %s", f)
		}
	}
	if !hasFinding(lint(cert, p), "EXT-002", Info) {
		t.Error("critical: optional should still report the observed criticality")
	}
}

// TestLintCriticalityOptionalAcceptsCritical verifies `critical: optional`
// accepts a critical extension too.
func TestLintCriticalityOptionalAcceptsCritical(t *testing.T) {
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				// Go emits Basic Constraints as critical.
				"basic_constraints": {Critical: section7.CriticalityOptional},
			},
		},
	}

	cert := createParsedTestCert(t, "example.com", "Test Org", "US", nil)

	for _, f := range lint(cert, p) {
		if f.RuleID == "EXT-002" && f.Severity == Error {
			t.Errorf("critical: optional must accept a critical extension, got: %s", f)
		}
	}
}

// ---------- Optional arcs ----------

// createCertWithPolicies builds a parsed certificate carrying the given
// certificate policy OIDs.
func createCertWithPolicies(t *testing.T, oids ...string) *x509.Certificate {
	t.Helper()

	// The modern Policies field is used rather than the deprecated
	// PolicyIdentifiers, which current Go releases no longer marshal.
	var policies []x509.OID
	for _, s := range oids {
		oid, err := x509.ParseOID(s)
		if err != nil {
			t.Fatalf("bad OID %q: %v", s, err)
		}
		policies = append(policies, oid)
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		Policies:              policies,
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

// policyArcProfile permits one required policy plus the Sectigo arc.
func policyArcProfile() section7.Profile {
	ca := false
	return section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: fixtureSignature(),
			PublicKey:          fixtureKey(),
			Issuer:             fixtureDN(),
			Subject:            fixtureDN(),
			Extensions: map[string]section7.Extension{
				"certificate_policies": {
					Required:       section7.PresenceRequired,
					RequiredValues: []string{"2.23.140.1.2.1"},
					OptionalArcs:   []string{"1.3.6.1.4.1.6449.*"},
				},
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
			},
		},
	}
}

// TestLintPolicyUnderArcAccepted verifies a policy beneath a permitted arc is
// accepted rather than reported as unlisted.
func TestLintPolicyUnderArcAccepted(t *testing.T) {
	p := policyArcProfile()
	cert := createCertWithPolicies(t, "2.23.140.1.2.1", "1.3.6.1.4.1.6449.1.2.2.7")

	for _, f := range section7.Lint(cert, p) {
		if f.Severity == section7.Error {
			t.Errorf("a policy under a permitted arc must not error, got: %s", f)
		}
	}

	found := false
	for _, f := range section7.Lint(cert, p) {
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
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-016" && f.Severity == section7.Error && strings.Contains(f.Message, "1.2.3.4.5") {
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
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-016" && f.Severity == section7.Error && strings.Contains(f.Message, "64499") {
			found = true
		}
	}
	if !found {
		t.Error("an OID sharing only a text prefix with the arc should be reported")
	}
}

// ---------- Precertificates vs final certificates ----------

// ctProfile describes both kinds of certificate, as a CT-logging profile must.
func ctProfile() section7.Profile {
	ca := false
	return section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: fixtureSignature(),
			PublicKey:          fixtureKey(),
			Issuer:             fixtureDN(),
			Subject:            fixtureDN(),
			Extensions: map[string]section7.Extension{
				"signed_certificate_timestamps": {Required: section7.PresenceFinalOnly},
				"precertificate_poison": {
					Required: section7.PresencePrecertificateOnly,
					Critical: section7.CriticalityRequired,
				},
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
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

// TestCertEKUOIDs verifies recognized and unrecognized EKUs are both returned
// as dotted OIDs, in certificate order.
func TestCertEKUOIDs(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 2, 3, 4}},
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

	got := certEKUOIDs(cert)
	want := []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.2.3.4"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("certEKUOIDs = %v, want %v", got, want)
	}

	if got := certEKUOIDs(createParsedTestCert(t, "example.com", "Test Org", "US", nil)); len(got) != 0 {
		t.Errorf("a certificate without EKUs should yield none, got %v", got)
	}
}

// TestEKUDisplay verifies known EKUs are named and unknown ones left bare.
func TestEKUDisplay(t *testing.T) {
	if got, want := ekuDisplay("1.3.6.1.5.5.7.3.1"), "serverAuth (1.3.6.1.5.5.7.3.1)"; got != want {
		t.Errorf("ekuDisplay(serverAuth) = %q, want %q", got, want)
	}
	if got, want := ekuDisplay("1.2.3.4"), "1.2.3.4"; got != want {
		t.Errorf("ekuDisplay(unknown) = %q, want %q", got, want)
	}
}

// TestLintPrecertificateAccepted verifies a well-formed Precertificate passes:
// poison present, no SCTs.
func TestLintPrecertificateAccepted(t *testing.T) {
	cert := certWithCTExtensions(t, true, false)

	for _, f := range section7.Lint(cert, ctProfile()) {
		if f.Severity == section7.Error {
			t.Errorf("a well-formed Precertificate must not error, got: %s", f)
		}
	}
}

// TestLintFinalCertificateAccepted verifies a well-formed final certificate
// passes: SCTs present, no poison.
func TestLintFinalCertificateAccepted(t *testing.T) {
	cert := certWithCTExtensions(t, false, true)

	for _, f := range section7.Lint(cert, ctProfile()) {
		if f.Severity == section7.Error {
			t.Errorf("a well-formed final certificate must not error, got: %s", f)
		}
	}
}

// TestLintPrecertificateWithSCTsRejected verifies SCTs are forbidden in a
// Precertificate.
func TestLintPrecertificateWithSCTsRejected(t *testing.T) {
	cert := certWithCTExtensions(t, true, true)

	found := false
	for _, f := range section7.Lint(cert, ctProfile()) {
		if f.RuleID == "EXT-017" && f.Severity == section7.Error &&
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
	for _, f := range section7.Lint(cert, ctProfile()) {
		if f.RuleID == "EXT-011" && f.Severity == section7.Error &&
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

	for _, f := range section7.Lint(cert, ctProfile()) {
		if f.RuleID == "EXT-011" && strings.Contains(f.Message, "signed_certificate_timestamps") {
			t.Errorf("a Precertificate must not be required to carry SCTs, got: %s", f)
		}
	}
}

// TestLintPrecertificateWarnsWhenProfileSilent verifies a profile that does not
// describe Precertificates says so rather than silently mis-linting.
func TestLintPrecertificateWarnsWhenProfileSilent(t *testing.T) {
	ca := false
	p := section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
			},
		},
	}

	cert := certWithCTExtensions(t, true, false)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "CT-001" && f.Severity == section7.Warning {
			found = true
		}
	}
	if !found {
		t.Error("a profile silent about Precertificates should produce a warning")
	}
}

// ---------- Alternative name types ----------

// sanProfile permits only the given general name types.
func sanProfile(required, optional []string) section7.Profile {
	ca := false
	return section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: fixtureSignature(),
			PublicKey:          fixtureKey(),
			Issuer:             fixtureDN(),
			Subject:            fixtureDN(),
			Extensions: map[string]section7.Extension{
				"subject_alt_name": {
					Required:       section7.PresenceRequired,
					Critical:       section7.CriticalityOptional,
					RequiredValues: required,
					OptionalValues: optional,
				},
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
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

	for _, f := range section7.Lint(cert, p) {
		if f.Severity == section7.Error {
			t.Errorf("listed name types must not error, got: %s", f)
		}
	}
}

// TestLintGeneralNameTypeNotListed verifies an unlisted name type is reported.
func TestLintGeneralNameTypeNotListed(t *testing.T) {
	p := sanProfile(nil, []string{"dns_name", "ip_address"})
	cert := certWithSANs(t, []string{"example.com"}, []string{"admin@example.com"}, nil)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-019" && f.Severity == section7.Error && strings.Contains(f.Message, "rfc822Name") {
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
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-018" && f.Severity == section7.Error && strings.Contains(f.Message, "dNSName") {
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

	for _, f := range section7.Lint(cert, p) {
		if f.Severity == section7.Error {
			t.Errorf("alias name types must be accepted, got: %s", f)
		}
	}
}

// ---------- CRL distribution points ----------

// crldpProfile permits distribution points of the given shape.
func crldpProfile(dps ...section7.DistributionPoint) section7.Profile {
	ca := false
	return section7.Profile{
		Profile: section7.Meta{Name: "Test Profile"},
		Requirements: section7.Requirements{
			SignatureAlgorithm: fixtureSignature(),
			PublicKey:          fixtureKey(),
			Issuer:             fixtureDN(),
			Subject:            fixtureDN(),
			Extensions: map[string]section7.Extension{
				"crl_distribution_points": {
					Required:           section7.PresenceRequired,
					DistributionPoints: dps,
				},
				"basic_constraints": {Required: section7.PresenceRequired, Critical: section7.CriticalityRequired, CA: &ca},
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
	p := crldpProfile(section7.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
		Required: true,
	})
	cert := certWithCRLDP(t, fullNameDP(t, 6))

	for _, f := range section7.Lint(cert, p) {
		if f.Severity == section7.Error {
			t.Errorf("a URI distribution point must not error, got: %s", f)
		}
	}
}

// TestLintCRLDistributionPointUnlistedNameType verifies a name type outside the
// profile is reported.
func TestLintCRLDistributionPointUnlistedNameType(t *testing.T) {
	p := crldpProfile(section7.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
	})
	// Tag 4 is directoryName, which the profile does not permit.
	cert := certWithCRLDP(t, fullNameDP(t, 6, 4))

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-021" && f.Severity == section7.Error && strings.Contains(f.Message, "directoryName") {
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
	p := crldpProfile(section7.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
	})

	body := append(fullNameDP(t, 6), ctx(t, 1, false, []byte{0x01, 0x02})...)
	cert := certWithCRLDP(t, body)

	found := false
	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-021" && f.Severity == section7.Error && strings.Contains(f.Message, "reasons") {
			found = true
		}
	}
	if !found {
		t.Error("an undeclared reasons field should be reported")
	}
}

// TestLintCRLDistributionPointDeclaredReasons verifies it passes once declared.
func TestLintCRLDistributionPointDeclaredReasons(t *testing.T) {
	p := crldpProfile(section7.DistributionPoint{
		FullName: []string{"uniform_resource_identifier"},
		Reasons:  true,
	})

	body := append(fullNameDP(t, 6), ctx(t, 1, false, []byte{0x01, 0x02})...)
	cert := certWithCRLDP(t, body)

	for _, f := range section7.Lint(cert, p) {
		if f.RuleID == "EXT-021" {
			t.Errorf("a declared reasons field must not be reported, got: %s", f)
		}
	}
}

// TestProfileValidationError tests that ValidateProfile rejects invalid profiles.
// This is tested by calling ValidateProfile directly, not by running main.
func TestProfileValidationError(t *testing.T) {
	invalidProfile := &section7.Profile{
		Profile: section7.Meta{Name: "Invalid Profile"},
		Requirements: section7.Requirements{
			Extensions: map[string]section7.Extension{
				"made_up_extension": {Critical: section7.CriticalityForbidden},
			},
		},
	}

	errs := section7.ValidateProfile(invalidProfile)
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
			Finding{RuleID: "TEST-001", Severity: section7.Error, Message: "Test error"},
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

// fixtureDN lists the one attribute the fixture certificates carry in their
// subject and, being self-signed, in their issuer too. The attribute list is
// exhaustive, so a profile used with those certificates must describe it even
// when the test is about extensions.
func fixtureDN() section7.DistinguishedName {
	return section7.DistinguishedName{
		Attributes: map[string]section7.Field{"common_name": {}},
	}
}

// fixtureSignature and fixtureKey describe how the fixture certificates are
// signed and keyed. A profile used with them has to say so: an algorithm a
// profile does not list is not permitted.
func fixtureSignature() section7.SignatureAlgorithm {
	return section7.SignatureAlgorithm{
		Allowed: []string{"sha256WithRSAEncryption", "ecdsa-with-SHA256"},
	}
}

func fixtureKey() section7.PublicKey {
	return section7.PublicKey{
		Algorithms: []section7.KeyAlgorithm{
			{Name: "rsaEncryption", KeySizes: []int{2048}},
			{Name: "id-ecPublicKey", Curves: []string{"P-256"}},
		},
	}
}
