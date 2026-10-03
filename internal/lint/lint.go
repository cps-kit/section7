package lint

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"section7/internal/profile"
)

// ---------- Finding ----------

// Severity classifies a lint finding.
type Severity string

const (
	Error   Severity = "ERROR"
	Warning Severity = "WARNING"
	Info    Severity = "INFO"
)

// Finding is a single observation made while linting a certificate.
type Finding struct {
	RuleID   string
	Severity Severity
	Message  string
}

func (f Finding) String() string {
	if f.RuleID != "" {
		return fmt.Sprintf("[%s] %s: %s", f.Severity, f.RuleID, f.Message)
	}
	return fmt.Sprintf("[%s] %s", f.Severity, f.Message)
}

// Counts returns the number of error, warning and info findings.
func Counts(findings []Finding) (errors, warnings, infos int) {
	for _, f := range findings {
		switch f.Severity {
		case Error:
			errors++
		case Warning:
			warnings++
		default:
			infos++
		}
	}
	return
}

// ---------- Subject field helpers ----------

// SubjectValues maps canonical profile subject attribute keys to the actual
// values in the certificate's Subject DN.
//
// The structured pkix.Name fields are used first, so that certificates which
// have not been round-tripped through parsing still resolve. Any further
// attribute types are then taken from Subject.Names, which is what makes
// attributes outside the structured set (postal codes, business category,
// jurisdiction fields and so on) visible to the linter.
func SubjectValues(cert *x509.Certificate) map[string][]string {
	values := map[string][]string{}

	add := func(key string, vals ...string) {
		for _, v := range vals {
			if v != "" {
				values[key] = append(values[key], v)
			}
		}
	}

	add("common_name", cert.Subject.CommonName)
	add("serial_number", cert.Subject.SerialNumber)
	add("organization_name", cert.Subject.Organization...)
	add("organizational_unit_name", cert.Subject.OrganizationalUnit...)
	add("country_name", cert.Subject.Country...)
	add("state_or_province_name", cert.Subject.Province...)
	add("locality_name", cert.Subject.Locality...)
	add("street_address", cert.Subject.StreetAddress...)
	add("postal_code", cert.Subject.PostalCode...)

	// Fill in any attribute type not covered by the structured fields.
	for _, atv := range cert.Subject.Names {
		key := profile.SubjectAttributeName(atv.Type.String())
		if key == "" {
			// Not a well-known attribute; key it by OID so that profiles
			// listing it by OID still match.
			key = atv.Type.String()
		}
		if _, already := values[key]; already {
			continue
		}
		if s, ok := atv.Value.(string); ok {
			add(key, s)
		} else {
			add(key, fmt.Sprintf("%v", atv.Value))
		}
	}

	return values
}

// IsPrecertificate reports whether the certificate is an RFC 6962
// Precertificate, which is identified by the critical poison extension.
func IsPrecertificate(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.String() == profile.PrecertificatePoisonOID {
			return true
		}
	}
	return false
}

// CertificateKind names the kind of certificate for use in messages.
func CertificateKind(cert *x509.Certificate) string {
	if IsPrecertificate(cert) {
		return "Precertificate"
	}
	return "final certificate"
}

// CertGeneralNameTags returns the context-specific tags present in the named
// GeneralNames extension, de-duplicated and in order of first appearance. The
// second result reports whether the extension itself is present.
//
// The raw extension is parsed rather than using the convenience fields of
// x509.Certificate, because those cover only four of the nine alternatives and
// would leave the rest invisible to the exhaustiveness check.
func CertGeneralNameTags(cert *x509.Certificate, extName string) ([]int, bool) {
	extOID, ok := profile.ExtensionOID(extName)
	if !ok {
		return nil, false
	}

	for _, e := range cert.Extensions {
		if e.Id.String() != extOID {
			continue
		}

		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(e.Value, &seq); err != nil {
			// Malformed contents: the extension is present but unreadable.
			return nil, true
		}
		return generalNameTags(seq.Bytes), true
	}
	return nil, false
}

// DistributionPointInfo records which components a DistributionPoint in a
// certificate actually uses, so that they can be checked against the profile.
type DistributionPointInfo struct {
	// FullNameTags are the GeneralName tags appearing in the fullName.
	FullNameTags []int
	// HasFullName reports the fullName form of DistributionPointName.
	HasFullName bool
	// HasNameRelativeToCRLIssuer reports the alternative form.
	HasNameRelativeToCRLIssuer bool
	// HasReasons reports the optional reasons field.
	HasReasons bool
	// HasCRLIssuer reports the optional cRLIssuer field.
	HasCRLIssuer bool
}

// CertDistributionPoints returns the distribution points of the named CRL
// extension. The second result reports whether the extension is present.
func CertDistributionPoints(cert *x509.Certificate, extName string) ([]DistributionPointInfo, bool) {
	extOID, ok := profile.ExtensionOID(extName)
	if !ok {
		return nil, false
	}

	for _, e := range cert.Extensions {
		if e.Id.String() != extOID {
			continue
		}

		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(e.Value, &seq); err != nil {
			return nil, true
		}

		var points []DistributionPointInfo
		rest := seq.Bytes
		for len(rest) > 0 {
			var dp asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &dp)
			if err != nil {
				break
			}

			info := DistributionPointInfo{}
			fields := dp.Bytes
			for len(fields) > 0 {
				var field asn1.RawValue
				fields, err = asn1.Unmarshal(fields, &field)
				if err != nil {
					break
				}
				if field.Class != asn1.ClassContextSpecific {
					continue
				}
				switch field.Tag {
				case 0: // distributionPoint [0] DistributionPointName
					var choice asn1.RawValue
					if _, err := asn1.Unmarshal(field.Bytes, &choice); err != nil {
						continue
					}
					switch choice.Tag {
					case 0: // fullName [0] GeneralNames
						info.HasFullName = true
						info.FullNameTags = generalNameTags(choice.Bytes)
					case 1: // nameRelativeToCRLIssuer [1]
						info.HasNameRelativeToCRLIssuer = true
					}
				case 1: // reasons [1] ReasonFlags
					info.HasReasons = true
				case 2: // cRLIssuer [2] GeneralNames
					info.HasCRLIssuer = true
				}
			}
			points = append(points, info)
		}
		return points, true
	}
	return nil, false
}

// generalNameTags returns the de-duplicated context-specific tags of a
// GeneralNames body.
func generalNameTags(body []byte) []int {
	var tags []int
	seen := map[int]bool{}
	rest := body
	for len(rest) > 0 {
		var name asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &name)
		if err != nil {
			break
		}
		if name.Class != asn1.ClassContextSpecific || seen[name.Tag] {
			continue
		}
		seen[name.Tag] = true
		tags = append(tags, name.Tag)
	}
	return tags
}

// generalNameDisplay renders a GeneralName tag as "name [tag]" when the tag is
// known, and as "[tag]" otherwise.
func generalNameDisplay(tag int) string {
	if name := profile.GeneralNameByTag(tag); name != "" {
		return fmt.Sprintf("'%s' [%d]", profile.GeneralNameLabel(name), tag)
	}
	return fmt.Sprintf("[%d]", tag)
}

// policyDisplay renders a certificate policy OID as "name (oid)" when the OID
// is well known, and as the bare OID otherwise.
func policyDisplay(oid string) string {
	if name := profile.PolicyName(oid); name != "" {
		return fmt.Sprintf("'%s' (%s)", name, oid)
	}
	return oid
}

// accessDescription mirrors the ASN.1 AccessDescription structure of RFC 5280:
//
//	AccessDescription ::= SEQUENCE {
//	    accessMethod    OBJECT IDENTIFIER,
//	    accessLocation  GeneralName }
//
// The location is kept as a raw value because GeneralName is a CHOICE and its
// contents are not needed to check which access methods are present.
type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// CertAccessMethodOIDs returns the access method OIDs present in the named
// information access extension, de-duplicated and in order of first appearance.
// The second result reports whether the extension itself is present.
func CertAccessMethodOIDs(cert *x509.Certificate, extName string) ([]string, bool) {
	extOID, ok := profile.ExtensionOID(extName)
	if !ok {
		return nil, false
	}

	for _, e := range cert.Extensions {
		if e.Id.String() != extOID {
			continue
		}
		var descriptions []accessDescription
		if _, err := asn1.Unmarshal(e.Value, &descriptions); err != nil {
			// Malformed contents: the extension is present but unreadable.
			return nil, true
		}
		var oids []string
		seen := map[string]bool{}
		for _, d := range descriptions {
			oid := d.Method.String()
			if !seen[oid] {
				seen[oid] = true
				oids = append(oids, oid)
			}
		}
		return oids, true
	}
	return nil, false
}

// accessMethodDisplay renders an access method OID as "name (oid)" when the OID
// is well known, and as the bare OID otherwise.
func accessMethodDisplay(oid string) string {
	if name := profile.AccessMethodName(oid); name != "" {
		return fmt.Sprintf("'%s' (%s)", name, oid)
	}
	return oid
}

// CertSubjectAttributeOIDs returns the OIDs of every attribute type present in
// the certificate's Subject DN, de-duplicated and in a stable order.
func CertSubjectAttributeOIDs(cert *x509.Certificate) []string {
	var oids []string
	seen := map[string]bool{}
	for _, atv := range cert.Subject.Names {
		oid := atv.Type.String()
		if !seen[oid] {
			seen[oid] = true
			oids = append(oids, oid)
		}
	}
	return oids
}

// subjectAttrDisplay renders a subject attribute OID as "name (oid)" when the
// OID is well known, and as the bare OID otherwise.
func subjectAttrDisplay(oid string) string {
	if key := profile.SubjectAttributeName(oid); key != "" {
		return fmt.Sprintf("'%s' (%s)", profile.SubjectAttributeLabel(key), oid)
	}
	return oid
}

// extensionDisplay renders an extension OID as "name (oid)" when the OID is
// well known, and as the bare OID otherwise.
func extensionDisplay(oid string) string {
	if name := profile.ExtensionName(oid); name != "" {
		return fmt.Sprintf("'%s' (%s)", name, oid)
	}
	return oid
}

// isEmptySubject reports whether the certificate's Subject DN is an empty
// SEQUENCE, i.e. carries no attributes at all.
func isEmptySubject(cert *x509.Certificate) bool {
	for _, vals := range SubjectValues(cert) {
		for _, v := range vals {
			if v != "" {
				return false
			}
		}
	}
	// Any attribute type outside the well-known set still counts as present.
	return len(cert.Subject.Names) == 0
}

// ---------- Extension helpers ----------

// ekuOIDs maps the extended key usages Go parses natively to their OIDs, so
// that profile entries written either as a name or as a raw OID can be
// compared against the certificate on a single, unambiguous basis.
var ekuOIDs = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "2.5.29.37.0",
	x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth:                     "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
	x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
	x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

// CertEKUOIDs returns the OIDs of every extended key usage present in the
// certificate, including those Go does not recognize natively.
func CertEKUOIDs(cert *x509.Certificate) []string {
	var oids []string
	for _, e := range cert.ExtKeyUsage {
		if oid, ok := ekuOIDs[e]; ok {
			oids = append(oids, oid)
		} else {
			oids = append(oids, fmt.Sprintf("unknown(%d)", int(e)))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		oids = append(oids, oid.String())
	}
	return oids
}

// EKUDisplay renders an EKU OID as "name (oid)" when the OID is well known,
// and as the bare OID otherwise.
func EKUDisplay(oid string) string {
	if name := profile.ExtKeyUsageName(oid); name != "" {
		return fmt.Sprintf("%s (%s)", name, oid)
	}
	return oid
}

var keyUsageNames = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"keyCertSign":       x509.KeyUsageCertSign,
	"cRLSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

// extIsCritical reports whether a named extension is marked critical, and
// whether it is present in the certificate at all. The extension may be named
// by any key the profile can express: a well-known name or a raw OID.
func extIsCritical(cert *x509.Certificate, name string) (bool, bool) {
	oid, ok := profile.ExtensionOID(name)
	if !ok {
		return false, false
	}
	for _, e := range cert.Extensions {
		if e.Id.String() == oid {
			return e.Critical, true
		}
	}
	return false, false
}

// CertPolicyOIDs returns the certificate policy OIDs present in the certificate.
//
// Both the modern Policies field and the legacy PolicyIdentifiers field are
// consulted, since which one is populated depends on the Go version and on how
// the certificate was created.
func CertPolicyOIDs(cert *x509.Certificate) []string {
	var oids []string
	seen := map[string]bool{}

	add := func(oid string) {
		if oid != "" && !seen[oid] {
			seen[oid] = true
			oids = append(oids, oid)
		}
	}

	for _, oid := range cert.Policies {
		add(oid.String())
	}
	for _, oid := range cert.PolicyIdentifiers {
		add(oid.String())
	}
	return oids
}

// CertMatchesProfile reports whether the certificate carries the policy OID by
// which the profile says its certificates can be recognized.
func CertMatchesProfile(cert *x509.Certificate, p profile.Profile) bool {
	want := p.Profile.RecognizedBy.PolicyOID
	if want == "" {
		return false
	}
	for _, got := range CertPolicyOIDs(cert) {
		if got == want {
			return true
		}
	}
	return false
}

// ---------- Lint ----------

// durationDays renders a validity period in whole days, keeping any remainder
// visible so that a period slightly over the limit is not reported as if it
// were exactly at the limit.
func durationDays(d time.Duration) string {
	days := int(d.Hours()) / 24
	rest := d - time.Duration(days)*24*time.Hour
	if rest <= 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d days %s", days, rest.Round(time.Second))
}

// Lint checks a certificate against a profile and returns all findings.
func Lint(cert *x509.Certificate, p profile.Profile) []Finding {
	var findings []Finding

	add := func(sev Severity, ruleID, msg string) {
		findings = append(findings, Finding{RuleID: ruleID, Severity: sev, Message: msg})
	}

	// ---- Certificate Transparency: which kind of certificate is this? ----
	// A Precertificate carries the poison extension and no SCTs; the final
	// certificate is the exact opposite. Presence requirements are evaluated
	// against whichever kind this is.
	isPrecertificate := IsPrecertificate(cert)
	certKind := CertificateKind(cert)

	if isPrecertificate {
		add(Info, "CT-001", "certificate is a Precertificate (poison extension present)")
		if !p.Requirements.CoversPrecertificates() {
			add(Warning, "CT-001",
				"the profile does not describe Precertificates, so this certificate is being "+
					"linted as though it were a final certificate")
		}
	}

	// ---- Recognition (certificate policy OID) ----
	if oid := p.Profile.RecognizedBy.PolicyOID; oid != "" {
		if CertMatchesProfile(cert, p) {
			add(Info, "POLICY-001", fmt.Sprintf(
				"certificate contains the profile Policy OID %s", oid))
		} else {
			add(Error, "POLICY-001", fmt.Sprintf(
				"certificate does not contain the required Policy OID %s (found: %s)",
				oid, strings.Join(CertPolicyOIDs(cert), ", ")))
		}
	}

	// ---- Validity ----
	if p.Requirements.Validity.MaximumDays > 0 {
		maxDur := time.Duration(p.Requirements.Validity.MaximumDays) * 24 * time.Hour
		actual := cert.NotAfter.Sub(cert.NotBefore)
		// Allow a 1-second rounding buffer
		if actual > maxDur+time.Second {
			add(Error, "VALIDITY-001", fmt.Sprintf(
				"validity period is %s, maximum allowed is %d days",
				durationDays(actual), p.Requirements.Validity.MaximumDays))
		} else {
			add(Info, "VALIDITY-001", fmt.Sprintf(
				"validity period OK (%s ≤ %d days)",
				durationDays(actual), p.Requirements.Validity.MaximumDays))
		}
	}

	// ---- Serial number ----
	if sn := p.Requirements.SerialNumber; sn.Required {
		switch {
		case cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0:
			add(Error, "SERIAL-001", "serial number is required but is absent or zero")
		case cert.SerialNumber.Sign() < 0:
			add(Error, "SERIAL-001", fmt.Sprintf(
				"serial number must be greater than zero, got %s", cert.SerialNumber))
		case len(cert.SerialNumber.Bytes()) > 20:
			// RFC 5280 limits the serial number to 20 octets.
			add(Error, "SERIAL-001", fmt.Sprintf(
				"serial number must not exceed 20 octets, got %d", len(cert.SerialNumber.Bytes())))
		default:
			// All mandatory checks passed; now verify profile-specified constraints.
			snLen := len(cert.SerialNumber.Bytes())
			bitLength := cert.SerialNumber.BitLen()

			// Check: maximum bit length constraint (if specified in profile)
			if sn.MaximumBitLength > 0 && bitLength > sn.MaximumBitLength {
				add(Warning, "SERIAL-002", fmt.Sprintf(
					"serial number exceeds the profile limit of 2^%d (bit length: %d > %d)",
					sn.MaximumBitLength, bitLength, sn.MaximumBitLength))
			}

			// Check: minimum octets constraint (if specified in profile)
			if sn.MinimumOctets > 0 && snLen < sn.MinimumOctets {
				add(Warning, "SERIAL-003", fmt.Sprintf(
					"serial number should contain at least %d octets (%d bits) per profile "+
						"(actual: %d octets)", sn.MinimumOctets, sn.MinimumOctets*8, snLen))
			}

			add(Info, "SERIAL-001", fmt.Sprintf(
				"serial number OK (%d octets, %d bits)", snLen, bitLength))
		}
	}

	// ---- Subject ----
	subject := p.Requirements.Subject
	subjectPresent := !isEmptySubject(cert)

	if subject.Required && subjectPresent {
		add(Info, "SUBJECT-000", "subject distinguished name is present OK")
	}
	if subject.Required && !subjectPresent && !subject.AllowEmpty {
		add(Error, "SUBJECT-000", "subject distinguished name is required but is empty")
	}

	// A subject that is absent or empty is allowed to remain null when the
	// profile marks it as required. In that case, there is nothing to validate
	// against the individual attribute requirements.
	if subjectPresent {
		subjValues := SubjectValues(cert)
		for fieldName, req := range subject.Attributes {
			// Profile keys may be aliases or raw OIDs; resolve to the key that
			// SubjectValues uses.
			lookup, known := profile.CanonicalSubjectAttribute(fieldName)
			if !known {
				lookup = fieldName
			}
			vals := subjValues[lookup]
			present := len(vals) > 0 && vals[0] != ""

			// Findings name the attribute as it appears in RFC 5280.
			label := profile.SubjectAttributeLabel(fieldName)

			if req.Required && !present {
				add(Error, "SUBJECT-001", fmt.Sprintf("required subject attribute '%s' is missing", label))
				continue
			}
			if !present {
				continue
			}

			// Length checks (apply to first / only value).
			// Lengths are measured in characters, not bytes: RFC 5280 upper
			// bounds are expressed as a number of characters, and a non-ASCII
			// character such as U+2019 would otherwise count as 2-4.
			val := vals[0]
			valLen := utf8.RuneCountInString(val)
			if req.Length.Min != nil && valLen < *req.Length.Min {
				add(Error, "SUBJECT-002", fmt.Sprintf(
					"subject attribute '%s' value %q is shorter than minimum length %d (actual: %d characters)",
					label, val, *req.Length.Min, valLen))
			}
			if req.Length.Max != nil && valLen > *req.Length.Max {
				add(Error, "SUBJECT-003", fmt.Sprintf(
					"subject attribute '%s' value %q exceeds maximum length %d (actual: %d characters)",
					label, val, *req.Length.Max, valLen))
			}

			if (req.Length.Min == nil || valLen >= *req.Length.Min) &&
				(req.Length.Max == nil || valLen <= *req.Length.Max) {
				add(Info, "SUBJECT-OK", fmt.Sprintf("subject attribute '%s' OK (%q)", label, val))
			}
		}

		// Any attribute present in the certificate but not listed in the
		// profile is not permitted. The attribute list is exhaustive, and a
		// profile that lists no attributes permits none: strictness is what a
		// profile gets for saying nothing.
		allowed := map[string]bool{}
		for name := range subject.Attributes {
			if oid, ok := profile.SubjectAttributeOID(name); ok {
				allowed[oid] = true
			}
		}
		for _, oid := range CertSubjectAttributeOIDs(cert) {
			if !allowed[oid] {
				add(Error, "SUBJECT-004", fmt.Sprintf(
					"subject attribute %s is present but not listed in the profile",
					subjectAttrDisplay(oid)))
			}
		}
	}

	// ---- Extensions ----
	for extName, req := range p.Requirements.Extensions {
		// BasicConstraints — CA flag
		if extName == "basic_constraints" && req.CA != nil {
			if *req.CA != cert.IsCA {
				add(Error, "EXT-001", fmt.Sprintf(
					"basicConstraints CA=%v but profile requires CA=%v", cert.IsCA, *req.CA))
			} else {
				add(Info, "EXT-001", fmt.Sprintf("basicConstraints CA=%v OK", cert.IsCA))
			}
		}

		// Presence and critical flag. Presence may depend on whether this is a
		// Precertificate or a final certificate.
		if critical, found := extIsCritical(cert, extName); found {
			if req.Required.ForbiddenIn(isPrecertificate) {
				add(Error, "EXT-017", fmt.Sprintf(
					"extension '%s' is present but must not appear in a %s (profile requires %s)",
					extName, certKind, req.Required.Spelling()))
			}
			switch {
			case !req.Critical.Allows(critical):
				add(Error, "EXT-002", fmt.Sprintf(
					"extension '%s' critical=%v but profile requires critical=%s",
					extName, critical, req.Critical.Spelling()))
			case req.Critical == profile.CriticalityOptional:
				add(Info, "EXT-002", fmt.Sprintf(
					"extension '%s' critical=%v OK (either is permitted)", extName, critical))
			default:
				add(Info, "EXT-002", fmt.Sprintf("extension '%s' critical=%v OK", extName, critical))
			}
		} else if req.Required.RequiredIn(isPrecertificate) {
			add(Error, "EXT-011", fmt.Sprintf(
				"extension '%s' is required in a %s but is not present in the certificate",
				extName, certKind))
		} else if req.Required.ForbiddenIn(isPrecertificate) {
			add(Info, "EXT-010", fmt.Sprintf(
				"extension '%s' is correctly absent from this %s", extName, certKind))
		} else {
			// Permitted but not mandated. Report the absence so that the
			// checks skipped for it are not silent.
			add(Info, "EXT-010", fmt.Sprintf(
				"extension '%s' is permitted by the profile but is not present in the certificate", extName))
		}

		// Access descriptions (Authority / Subject Information Access)
		if len(req.AccessDescriptions) > 0 {
			methods, extPresent := CertAccessMethodOIDs(cert, extName)
			if extPresent {
				present := map[string]bool{}
				for _, oid := range methods {
					present[oid] = true
				}

				allowed := map[string]bool{}
				for _, ad := range req.AccessDescriptions {
					oid, known := profile.AccessMethodOID(ad.AccessMethod)
					if !known {
						add(Warning, "EXT-012", fmt.Sprintf(
							"unknown access method '%s' in profile", ad.AccessMethod))
						continue
					}
					allowed[oid] = true

					switch {
					case present[oid]:
						add(Info, "EXT-012", fmt.Sprintf(
							"extension '%s' access method %s present OK",
							extName, accessMethodDisplay(oid)))
					case ad.Required:
						add(Error, "EXT-012", fmt.Sprintf(
							"extension '%s' is missing required access method %s",
							extName, accessMethodDisplay(oid)))
					default:
						add(Info, "EXT-012", fmt.Sprintf(
							"extension '%s' optional access method %s is not present",
							extName, accessMethodDisplay(oid)))
					}
				}

				// The access method list is exhaustive.
				for _, oid := range methods {
					if !allowed[oid] {
						add(Error, "EXT-013", fmt.Sprintf(
							"extension '%s' contains access method %s which is not listed in the profile",
							extName, accessMethodDisplay(oid)))
					}
				}
			}
		}

		// CRL distribution points
		if len(req.DistributionPoints) > 0 {
			points, extPresent := CertDistributionPoints(cert, extName)
			if extPresent {
				// The permitted shape is the union of the profile's entries.
				allowedTags := map[int]bool{}
				allowRelative, allowReasons, allowIssuer := false, false, false
				for _, dp := range req.DistributionPoints {
					for _, v := range dp.FullName {
						if tag, known := profile.GeneralNameTag(v); known {
							allowedTags[tag] = true
						} else {
							add(Warning, "EXT-020", fmt.Sprintf(
								"unknown general name type '%s' in profile", v))
						}
					}
					allowRelative = allowRelative || dp.NameRelativeToCRLIssuer
					allowReasons = allowReasons || dp.Reasons
					allowIssuer = allowIssuer || dp.CRLIssuer
				}

				required := false
				for _, dp := range req.DistributionPoints {
					if dp.Required {
						required = true
					}
				}
				if required && len(points) == 0 {
					add(Error, "EXT-020", fmt.Sprintf(
						"extension '%s' contains no distribution point, but the profile requires one",
						extName))
				}

				for i, dp := range points {
					if dp.HasNameRelativeToCRLIssuer && !allowRelative {
						add(Error, "EXT-021", fmt.Sprintf(
							"extension '%s' distribution point %d names the CRL relative to its issuer, "+
								"which is not described in the profile", extName, i+1))
					}
					for _, tag := range dp.FullNameTags {
						if !allowedTags[tag] {
							add(Error, "EXT-021", fmt.Sprintf(
								"extension '%s' distribution point %d contains name type %s "+
									"which is not listed in the profile",
								extName, i+1, generalNameDisplay(tag)))
						}
					}
					if dp.HasReasons && !allowReasons {
						add(Error, "EXT-021", fmt.Sprintf(
							"extension '%s' distribution point %d specifies reasons, "+
								"which is not described in the profile", extName, i+1))
					}
					if dp.HasCRLIssuer && !allowIssuer {
						add(Error, "EXT-021", fmt.Sprintf(
							"extension '%s' distribution point %d specifies a CRL issuer, "+
								"which is not described in the profile", extName, i+1))
					}
				}

				if len(points) > 0 {
					add(Info, "EXT-020", fmt.Sprintf(
						"extension '%s' contains %d distribution point(s) OK", extName, len(points)))
				}
			}
		}

		// Alternative names (Subject / Issuer Alternative Name)
		if profile.SupportsGeneralNames(extName) && (len(req.RequiredValues) > 0 || len(req.OptionalValues) > 0) {
			tags, extPresent := CertGeneralNameTags(cert, extName)
			if extPresent {
				present := map[int]bool{}
				for _, tag := range tags {
					present[tag] = true
				}

				allowed := map[int]bool{}
				for _, required := range req.RequiredValues {
					tag, known := profile.GeneralNameTag(required)
					if !known {
						add(Warning, "EXT-018", fmt.Sprintf(
							"unknown general name type '%s' in profile", required))
						continue
					}
					allowed[tag] = true
					if !present[tag] {
						add(Error, "EXT-018", fmt.Sprintf(
							"extension '%s' is missing required name type %s",
							extName, generalNameDisplay(tag)))
					} else {
						add(Info, "EXT-018", fmt.Sprintf(
							"extension '%s' name type %s present OK", extName, generalNameDisplay(tag)))
					}
				}
				for _, opt := range req.OptionalValues {
					tag, known := profile.GeneralNameTag(opt)
					if !known {
						add(Warning, "EXT-018", fmt.Sprintf(
							"unknown general name type '%s' in profile", opt))
						continue
					}
					allowed[tag] = true
					if present[tag] {
						add(Info, "EXT-018", fmt.Sprintf(
							"extension '%s' optional name type %s present OK",
							extName, generalNameDisplay(tag)))
					}
				}

				// The name type list is exhaustive.
				for _, tag := range tags {
					if !allowed[tag] {
						add(Error, "EXT-019", fmt.Sprintf(
							"extension '%s' contains name type %s which is not listed in the profile",
							extName, generalNameDisplay(tag)))
					}
				}
			}
		}

		// Extended Key Usage
		if extName == "extended_key_usage" && (len(req.RequiredValues) > 0 || len(req.OptionalValues) > 0 || len(req.OptionalArcs) > 0) {
			present := map[string]bool{}
			for _, oid := range CertEKUOIDs(cert) {
				present[oid] = true
			}

			allowed := map[string]bool{}
			for _, required := range req.RequiredValues {
				oid, known := profile.ExtKeyUsageOID(required)
				if !known {
					add(Warning, "EXT-003", fmt.Sprintf("unknown EKU value '%s' in profile", required))
					continue
				}
				allowed[oid] = true
				if !present[oid] {
					add(Error, "EXT-003", fmt.Sprintf(
						"required EKU '%s' is missing from certificate", EKUDisplay(oid)))
				} else {
					add(Info, "EXT-003", fmt.Sprintf("EKU '%s' present OK", EKUDisplay(oid)))
				}
			}
			for _, opt := range req.OptionalValues {
				oid, known := profile.ExtKeyUsageOID(opt)
				if !known {
					add(Warning, "EXT-005", fmt.Sprintf("unknown EKU value '%s' in profile", opt))
					continue
				}
				allowed[oid] = true
				if present[oid] {
					add(Info, "EXT-005", fmt.Sprintf("optional EKU '%s' present OK", EKUDisplay(oid)))
				}
			}
			// Any EKU not listed as required or optional, and not falling under
			// a permitted arc, is not permitted.
			for _, oid := range CertEKUOIDs(cert) {
				if allowed[oid] {
					continue
				}
				if arc := profile.MatchingArc(oid, req.OptionalArcs); arc != "" {
					add(Info, "EXT-006", fmt.Sprintf(
						"EKU '%s' is permitted by arc %s", EKUDisplay(oid), arc))
					continue
				}
				add(Error, "EXT-006", fmt.Sprintf(
					"EKU '%s' is present but not listed as required or optional in the profile",
					EKUDisplay(oid)))
			}
		}

		// Certificate Policies
		if extName == "certificate_policies" && (len(req.RequiredValues) > 0 || len(req.OptionalValues) > 0 || len(req.OptionalArcs) > 0) {
			present := map[string]bool{}
			for _, oid := range CertPolicyOIDs(cert) {
				present[oid] = true
			}

			allowed := map[string]bool{}
			for _, required := range req.RequiredValues {
				oid, known := profile.PolicyOID(required)
				if !known {
					add(Warning, "EXT-014", fmt.Sprintf("unknown policy value '%s' in profile", required))
					continue
				}
				allowed[oid] = true
				if !present[oid] {
					add(Error, "EXT-014", fmt.Sprintf(
						"required certificate policy %s is missing from certificate", policyDisplay(oid)))
				} else {
					add(Info, "EXT-014", fmt.Sprintf("certificate policy %s present OK", policyDisplay(oid)))
				}
			}
			for _, opt := range req.OptionalValues {
				oid, known := profile.PolicyOID(opt)
				if !known {
					add(Warning, "EXT-015", fmt.Sprintf("unknown policy value '%s' in profile", opt))
					continue
				}
				allowed[oid] = true
				if present[oid] {
					add(Info, "EXT-015", fmt.Sprintf("optional certificate policy %s present OK", policyDisplay(oid)))
				}
			}
			// Any policy not listed as required or optional, and not falling
			// under a permitted arc, is not permitted.
			for _, oid := range CertPolicyOIDs(cert) {
				if allowed[oid] {
					continue
				}
				if arc := profile.MatchingArc(oid, req.OptionalArcs); arc != "" {
					add(Info, "EXT-016", fmt.Sprintf(
						"certificate policy %s is permitted by arc %s", policyDisplay(oid), arc))
					continue
				}
				add(Error, "EXT-016", fmt.Sprintf(
					"certificate policy %s is present but not listed as required or optional in the profile",
					policyDisplay(oid)))
			}
		}

		// Key Usage
		if extName == "key_usage" && (len(req.RequiredValues) > 0 || len(req.OptionalValues) > 0) {
			for _, required := range req.RequiredValues {
				ku, known := keyUsageNames[required]
				if !known {
					add(Warning, "EXT-004", fmt.Sprintf("unknown KeyUsage name '%s' in profile", required))
					continue
				}
				if cert.KeyUsage&ku == 0 {
					add(Error, "EXT-004", fmt.Sprintf("required KeyUsage '%s' is missing from certificate", required))
				} else {
					add(Info, "EXT-004", fmt.Sprintf("KeyUsage '%s' present OK", required))
				}
			}
			for _, opt := range req.OptionalValues {
				ku, known := keyUsageNames[opt]
				if !known {
					add(Warning, "EXT-007", fmt.Sprintf("unknown KeyUsage name '%s' in profile", opt))
					continue
				}
				if cert.KeyUsage&ku != 0 {
					add(Info, "EXT-007", fmt.Sprintf("optional KeyUsage '%s' present OK", opt))
				}
			}
			// Any KeyUsage bit not listed as required or optional is not permitted.
			var allowed x509.KeyUsage
			for _, name := range append(append([]string{}, req.RequiredValues...), req.OptionalValues...) {
				allowed |= keyUsageNames[name]
			}
			for name, bit := range keyUsageNames {
				if cert.KeyUsage&bit != 0 && allowed&bit == 0 {
					add(Error, "EXT-008", fmt.Sprintf(
						"KeyUsage '%s' is present but not listed as required or optional in the profile", name))
				}
			}
		}
	}

	// Any extension present in the certificate but not listed in the profile
	// is not permitted. The extension list is exhaustive: there are no
	// implicitly permitted extensions, so that the generated CPS section 7
	// text describes every extension a conforming certificate may contain.
	// A profile that lists no extensions permits none.
	allowed := map[string]bool{}
	for name := range p.Requirements.Extensions {
		if oid, ok := profile.ExtensionOID(name); ok {
			allowed[oid] = true
		}
	}
	for _, e := range cert.Extensions {
		oid := e.Id.String()
		if !allowed[oid] {
			add(Error, "EXT-009", fmt.Sprintf(
				"extension %s is present but not listed in the profile",
				extensionDisplay(oid)))
		}
	}

	return findings
}
