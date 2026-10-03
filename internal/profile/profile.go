package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------- YAML model ----------

type Profile struct {
	Profile      Meta         `yaml:"profile"`
	Requirements Requirements `yaml:"requirements"`
	Rules        []Rule       `yaml:"rules"`
}

type Meta struct {
	Name         string       `yaml:"name"`
	RecognizedBy RecognizedBy `yaml:"recognized_by"`
	Version      int          `yaml:"version"`
}

// RecognizedBy describes how certificates issued under this profile can be
// identified, e.g. by a certificate policy OID.
type RecognizedBy struct {
	PolicyOID string `yaml:"policy_oid"`
}

type Requirements struct {
	Validity     Validity             `yaml:"validity"`
	SerialNumber SerialNumber         `yaml:"serial_number"`
	Subject      Subject              `yaml:"subject"`
	Extensions   map[string]Extension `yaml:"extensions"`
}

// SerialNumber describes the requirements for the certificate serial number.
type SerialNumber struct {
	// Required indicates the serial number must be present and positive.
	Required bool `yaml:"required"`
	// MaximumBitLength constrains the maximum bit length of the serial number.
	// For example, a value of 159 enforces the constraint "less than 2^159".
	// If zero or omitted, no bit length constraint is enforced.
	MaximumBitLength int `yaml:"maximum_bit_length"`
	// MinimumOctets constrains the minimum number of octets (bytes) in the
	// serial number, expressing a minimum entropy requirement.
	// For example, a value of 8 enforces "at least 64 bits of entropy".
	// If zero or omitted, no minimum octets constraint is enforced.
	MinimumOctets int `yaml:"minimum_octets"`
	// TextualRequirement is prose reproduced verbatim in the generated CPS.
	// It expresses requirements (such as non-sequential numbers or CSPRNG entropy)
	// that cannot be verified by inspecting a certificate alone.
	TextualRequirement string `yaml:"textual_requirement"`

	// Declared records whether the profile contained a serial_number block.
	Declared bool `yaml:"-"`
}

// UnmarshalYAML records that the serial_number block was present.
func (s *SerialNumber) UnmarshalYAML(node *yaml.Node) error {
	type raw SerialNumber
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*s = SerialNumber(r)
	s.Declared = true
	return nil
}

// Subject describes the requirements for the certificate's Subject
// Distinguished Name as a whole, plus the individual attributes within it.
type Subject struct {
	// Required indicates whether the Subject DN must be present (non-empty).
	Required bool `yaml:"required"`
	// AllowEmpty indicates the Subject DN may be absent or empty even when the
	// profile marks it as required. This is useful for profiles where a null DN
	// is technically permitted but all subject attribute checks still apply when
	// the DN is present.
	AllowEmpty bool `yaml:"allow_empty"`
	// Attributes holds the per-attribute requirements, keyed by attribute name.
	// The list is exhaustive: an attribute that does not appear here is not
	// permitted in the certificate. A profile that omits the subject block
	// therefore permits no subject attributes at all.
	Attributes map[string]Field `yaml:"attributes"`
}

type Validity struct {
	MaximumDays int `yaml:"maximum_days"`
}

type FieldLength struct {
	Min *int `yaml:"min"`
	Max *int `yaml:"max"`
}

type Field struct {
	Required bool        `yaml:"required"`
	Length   FieldLength `yaml:"length"`
}

// Criticality expresses what a profile requires of an extension's criticality
// flag. It is written in YAML as `true`, `false`, or `optional`.
type Criticality int

const (
	// CriticalityForbidden requires the extension to be non-critical. This is
	// the default when `critical` is not specified.
	CriticalityForbidden Criticality = iota
	// CriticalityRequired requires the extension to be marked critical.
	CriticalityRequired
	// CriticalityOptional permits either, and so is never a violation.
	CriticalityOptional
)

// Allows reports whether an observed criticality flag satisfies the requirement.
func (c Criticality) Allows(critical bool) bool {
	switch c {
	case CriticalityRequired:
		return critical
	case CriticalityOptional:
		return true
	default:
		return !critical
	}
}

// String renders the requirement for documentation tables.
func (c Criticality) String() string {
	switch c {
	case CriticalityRequired:
		return "Yes"
	case CriticalityOptional:
		return "Optional"
	default:
		return "No"
	}
}

// Spelling renders the requirement as it is written in a profile, for use in
// diagnostic messages.
func (c Criticality) Spelling() string {
	switch c {
	case CriticalityRequired:
		return "true"
	case CriticalityOptional:
		return "optional"
	default:
		return "false"
	}
}

// UnmarshalYAML accepts `true`, `false`, or `optional`.
func (c *Criticality) UnmarshalYAML(node *yaml.Node) error {
	var b bool
	if err := node.Decode(&b); err == nil {
		if b {
			*c = CriticalityRequired
		} else {
			*c = CriticalityForbidden
		}
		return nil
	}

	var s string
	if err := node.Decode(&s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "optional", "any":
			*c = CriticalityOptional
			return nil
		}
	}

	return fmt.Errorf("extension 'critical' must be true, false, or optional (got %q)", node.Value)
}

// ---------- Certificate Transparency ----------

// PrecertificatePoisonOID is the critical poison extension of RFC 6962 that
// marks a Precertificate, so that it is never accepted as a certificate by
// relying parties.
const PrecertificatePoisonOID = "1.3.6.1.4.1.11129.2.4.3"

// SCTListOID is the Signed Certificate Timestamp List extension of RFC 6962,
// which carries the SCTs returned when the corresponding Precertificate was
// submitted to Certificate Transparency logs.
const SCTListOID = "1.3.6.1.4.1.11129.2.4.2"

// Presence expresses whether an extension must appear in a certificate, and in
// which kind of certificate. It is written in YAML as `true`, `false`,
// `final_only`, or `precertificate_only`.
//
// The distinction exists because a Precertificate and the final certificate it
// corresponds to differ by exactly these two extensions: a Precertificate
// carries the poison extension and no SCTs, while the final certificate carries
// the SCTs and no poison.
type Presence int

const (
	// PresenceOptional permits the extension without requiring it. This is the
	// default when `required` is not specified.
	PresenceOptional Presence = iota
	// PresenceRequired requires the extension in every certificate.
	PresenceRequired
	// PresenceFinalOnly requires the extension in final certificates and
	// forbids it in Precertificates.
	PresenceFinalOnly
	// PresencePrecertificateOnly requires the extension in Precertificates and
	// forbids it in final certificates.
	PresencePrecertificateOnly
)

// RequiredIn reports whether the extension must be present in a certificate of
// the given kind.
func (p Presence) RequiredIn(isPrecertificate bool) bool {
	switch p {
	case PresenceRequired:
		return true
	case PresenceFinalOnly:
		return !isPrecertificate
	case PresencePrecertificateOnly:
		return isPrecertificate
	default:
		return false
	}
}

// ForbiddenIn reports whether the extension must be absent from a certificate
// of the given kind.
func (p Presence) ForbiddenIn(isPrecertificate bool) bool {
	switch p {
	case PresenceFinalOnly:
		return isPrecertificate
	case PresencePrecertificateOnly:
		return !isPrecertificate
	default:
		return false
	}
}

// AppliesToPrecertificates reports whether the value distinguishes between the
// two kinds of certificate.
func (p Presence) AppliesToPrecertificates() bool {
	return p == PresenceFinalOnly || p == PresencePrecertificateOnly
}

// String renders the requirement for documentation tables.
func (p Presence) String() string {
	switch p {
	case PresenceRequired:
		return "Yes"
	case PresenceFinalOnly:
		return "Final certificates only"
	case PresencePrecertificateOnly:
		return "Precertificates only"
	default:
		return "No"
	}
}

// Spelling renders the requirement as it is written in a profile, for use in
// diagnostic messages.
func (p Presence) Spelling() string {
	switch p {
	case PresenceRequired:
		return "true"
	case PresenceFinalOnly:
		return "final_only"
	case PresencePrecertificateOnly:
		return "precertificate_only"
	default:
		return "false"
	}
}

// UnmarshalYAML accepts `true`, `false`, `final_only`, or `precertificate_only`.
func (p *Presence) UnmarshalYAML(node *yaml.Node) error {
	var b bool
	if err := node.Decode(&b); err == nil {
		if b {
			*p = PresenceRequired
		} else {
			*p = PresenceOptional
		}
		return nil
	}

	var s string
	if err := node.Decode(&s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "final_only", "final", "certificate_only":
			*p = PresenceFinalOnly
			return nil
		case "precertificate_only", "precertificate", "precert_only":
			*p = PresencePrecertificateOnly
			return nil
		}
	}

	return fmt.Errorf(
		"extension 'required' must be true, false, final_only, or precertificate_only (got %q)", node.Value)
}

// AccessDescription describes one entry of an information access extension,
// such as Authority Information Access.
type AccessDescription struct {
	// AccessMethod names the kind of access, either as a well-known name such
	// as `id-ad-ocsp` or as a raw OID.
	AccessMethod string `yaml:"access_method"`
	// Required indicates whether an entry with this access method must be
	// present in the extension.
	Required bool `yaml:"required"`
}

// DistributionPoint describes one entry of a CRL distribution point extension.
//
// The ASN.1 structure of RFC 5280 is:
//
//	DistributionPoint ::= SEQUENCE {
//	    distributionPoint [0] DistributionPointName OPTIONAL,
//	    reasons           [1] ReasonFlags OPTIONAL,
//	    cRLIssuer         [2] GeneralNames OPTIONAL }
//	DistributionPointName ::= CHOICE {
//	    fullName                [0] GeneralNames,
//	    nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
type DistributionPoint struct {
	// FullName lists the GeneralName types permitted in the fullName of the
	// distribution point. The list is exhaustive: a name of any other type
	// does not conform.
	FullName []string `yaml:"full_name"`
	// NameRelativeToCRLIssuer permits the alternative form of
	// DistributionPointName, which names the CRL relative to its issuer.
	NameRelativeToCRLIssuer bool `yaml:"name_relative_to_crl_issuer"`
	// Reasons permits the optional reasons field.
	Reasons bool `yaml:"reasons"`
	// CRLIssuer permits the optional cRLIssuer field.
	CRLIssuer bool `yaml:"crl_issuer"`
	// Required indicates whether at least one distribution point of this shape
	// must be present when the extension is present.
	Required bool `yaml:"required"`
}

// Extension describes the requirements for a single certificate extension.
type Extension struct {
	// Critical is the required state of the extension's criticality flag.
	Critical Criticality `yaml:"critical"`
	// CA is the required value of the cA boolean; basic_constraints only.
	CA *bool `yaml:"ca"`
	// Required indicates whether the extension must be present, and in which
	// kind of certificate. When PresenceOptional the extension is permitted
	// but not mandated.
	Required Presence `yaml:"required"`
	// RequiredValues lists values that must appear inside the extension.
	// Only meaningful for key_usage and extended_key_usage.
	RequiredValues []string `yaml:"required_values"`
	// OptionalValues lists values that may appear inside the extension.
	OptionalValues []string `yaml:"optional_values"`
	// OptionalArcs lists OID arcs, written with a trailing `.*` such as
	// `1.3.6.1.4.1.6449.*`, under which any identifier is permitted. Only
	// meaningful for extensions whose values are OIDs.
	OptionalArcs []string `yaml:"optional_arcs"`
	// AccessDescriptions lists the permitted access methods. Only meaningful
	// for authority_information_access and subject_information_access. The
	// list is exhaustive: access methods not listed are not permitted.
	AccessDescriptions []AccessDescription `yaml:"access_descriptions"`
	// DistributionPoints lists the permitted shapes of distribution point.
	// Only meaningful for crl_distribution_points and freshest_crl.
	DistributionPoints []DistributionPoint `yaml:"distribution_points"`
	// OID declares the object identifier of an extension that is not one of
	// the well-known extensions. It lets a profile name a vendor or otherwise
	// unregistered extension by a readable key while still identifying it
	// unambiguously in a certificate.
	OID string `yaml:"extension_oid"`

	// legacyRequiredList records that `required` was written as a list, which
	// is the pre-rename spelling of `required_values`. Reported by validation.
	legacyRequiredList bool
}

// UnmarshalYAML decodes an extension, tolerating the older spelling of
// `required` as a list so that validation can explain the rename instead of
// failing with an opaque type error.
func (e *Extension) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Critical           Criticality         `yaml:"critical"`
		CA                 *bool               `yaml:"ca"`
		Required           yaml.Node           `yaml:"required"`
		RequiredValues     []string            `yaml:"required_values"`
		OptionalValues     []string            `yaml:"optional_values"`
		OptionalArcs       []string            `yaml:"optional_arcs"`
		AccessDescriptions []AccessDescription `yaml:"access_descriptions"`
		DistributionPoints []DistributionPoint `yaml:"distribution_points"`
		OID                string              `yaml:"extension_oid"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}

	e.Critical = raw.Critical
	e.CA = raw.CA
	e.RequiredValues = raw.RequiredValues
	e.OptionalValues = raw.OptionalValues
	e.OptionalArcs = raw.OptionalArcs
	e.AccessDescriptions = raw.AccessDescriptions
	e.DistributionPoints = raw.DistributionPoints
	e.OID = strings.TrimSpace(raw.OID)

	switch raw.Required.Kind {
	case 0:
		// `required` absent: the extension is permitted but not mandated.
	case yaml.ScalarNode:
		// Presence.UnmarshalYAML reports the accepted spellings.
		if err := raw.Required.Decode(&e.Required); err != nil {
			return err
		}
	case yaml.SequenceNode:
		// Pre-rename spelling; ValidateProfile turns this into a clear message.
		e.legacyRequiredList = true
	default:
		return fmt.Errorf(
			"extension 'required' must be true, false, final_only, or precertificate_only")
	}
	return nil
}

// CoversPrecertificates reports whether the profile describes Precertificates
// as well as final certificates, which is the case when any extension
// requirement distinguishes between them.
func (r Requirements) CoversPrecertificates() bool {
	for _, ext := range r.Extensions {
		if ext.Required.AppliesToPrecertificates() {
			return true
		}
	}
	return false
}

type Rule struct {
	ID   string `yaml:"id"`
	Text string `yaml:"text"`
}

// ---------- Loader ----------

type Loaded struct {
	Profile Profile
	Raw     map[string]interface{}
}

func Load(path string) (*Loaded, error) {
	raw, err := resolve(path, nil)
	if err != nil {
		return nil, err
	}

	// The struct view is decoded from the resolved tree, so that inherited
	// content and content written in the profile itself are indistinguishable
	// to everything downstream.
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("resolving profile %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile struct: %w", err)
	}

	// Extensions that are not well known identify themselves by OID; make
	// those keys resolvable to the rest of the program.
	for name, ext := range p.Requirements.Extensions {
		if ext.OID == "" {
			continue
		}
		if err := RegisterExtension(name, ext.OID); err != nil {
			return nil, err
		}
	}

	return &Loaded{Profile: p, Raw: raw}, nil
}

// FragmentPrefix marks a file that exists to be inherited from rather than to
// be issued against. LoadDir skips such files, so a shared definition is never
// mistaken for a profile of its own.
const FragmentPrefix = "_"

// IsFragment reports whether a path names a shared definition file.
func IsFragment(path string) bool {
	return strings.HasPrefix(filepath.Base(path), FragmentPrefix)
}

// LoadDir loads every *.yaml / *.yml profile found in dir, skipping the shared
// definition files that profiles inherit from.
// The returned map is keyed by file path.
func LoadDir(dir string) (map[string]*Loaded, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading profile directory: %w", err)
	}

	result := map[string]*Loaded{}
	for _, e := range entries {
		if e.IsDir() || IsFragment(e.Name()) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		loaded, err := Load(path)
		if err != nil {
			return nil, err
		}
		result[path] = loaded
	}
	return result, nil
}

// ---------- Inheritance ----------

// ExtendsKey is the top-level key that names the files a profile inherits.
// It is resolved away by Load, so the rest of the program only ever sees a
// single, fully expanded profile.
const ExtendsKey = "extends"

// resolve reads path and merges it over everything it extends. Bases are
// merged in the order listed, and the extending file is merged last, so a
// profile always wins over what it inherits. The stack carries the files
// already being resolved, which is how an inheritance cycle is detected.
func resolve(path string, stack []string) (map[string]interface{}, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	for _, seen := range stack {
		if seen == abs {
			return nil, fmt.Errorf("profile inheritance cycle: %s is extended by itself", path)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing profile raw: %w", err)
	}
	if raw == nil {
		raw = map[string]interface{}{}
	}

	bases, err := extendsList(raw[ExtendsKey], path)
	if err != nil {
		return nil, err
	}
	delete(raw, ExtendsKey)
	if len(bases) == 0 {
		return raw, nil
	}

	merged := map[string]interface{}{}
	for _, base := range bases {
		basePath := base
		if !filepath.IsAbs(basePath) {
			basePath = filepath.Join(filepath.Dir(path), basePath)
		}
		// Each base is read afresh, so two profiles extending the same file
		// never share a subtree that one of them could edit for the other.
		baseRaw, err := resolve(basePath, append(stack, abs))
		if err != nil {
			return nil, fmt.Errorf("%s extends %s: %w", filepath.Base(path), base, err)
		}
		mergeInto(merged, baseRaw)
	}
	mergeInto(merged, raw)
	return merged, nil
}

// extendsList reads the `extends` value, which may name one file or several.
func extendsList(v interface{}, path string) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(t) == "" {
			return nil, fmt.Errorf("%s: '%s' names no file", path, ExtendsKey)
		}
		return []string{t}, nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("%s: every '%s' entry must be a file name", path, ExtendsKey)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: '%s' must be a file name or a list of file names", path, ExtendsKey)
	}
}

// mergeInto merges src over dst. Mappings are merged key by key, so a profile
// can add an extension or an attribute without restating the rest. Every other
// value, sequences included, replaces what it overrides, so a profile that
// narrows an inherited list states that list in full.
func mergeInto(dst, src map[string]interface{}) {
	for k, v := range src {
		if sub, ok := v.(map[string]interface{}); ok {
			if existing, ok := dst[k].(map[string]interface{}); ok {
				mergeInto(existing, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// IsValidOID reports whether s looks like a dotted-decimal object identifier.
func IsValidOID(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// ---------- Path interpolation (shared by generator and linter) ----------

// ResolvePath walks a map[string]interface{} tree using a dot-separated path.
// When the resolved value is a nested map it returns the key name as a
// human-readable label (snake_case → space-separated words).
func ResolvePath(data map[string]interface{}, path string) (string, bool) {
	parts := strings.SplitN(path, ".", 2)
	val, exists := data[parts[0]]
	if !exists {
		return "", false
	}
	if len(parts) == 1 {
		if _, isMap := val.(map[string]interface{}); isMap {
			words := strings.Split(parts[0], "_")
			return strings.Join(words, " "), true
		}
		return fmt.Sprintf("%v", val), true
	}
	nested, ok := val.(map[string]interface{})
	if !ok {
		return "", false
	}
	return ResolvePath(nested, parts[1])
}

// InterpolateText replaces {dot.separated.path} references in text with
// values looked up from the raw profile map.
func InterpolateText(text string, raw map[string]interface{}) string {
	for {
		start := strings.Index(text, "{")
		if start == -1 {
			break
		}
		end := strings.Index(text[start:], "}")
		if end == -1 {
			break
		}
		key := text[start+1 : start+end]
		if val, ok := ResolvePath(raw, key); ok {
			text = text[:start] + val + text[start+end+1:]
		} else {
			break
		}
	}
	return text
}

// ---------- Validation ----------

// SubjectAttributeMeta describes a subject DN attribute.
type SubjectAttributeMeta struct {
	// ASN1Name is the X.520 attribute type name, as used in RFC 5280
	// (for example `commonName`). This is the name used in generated documents
	// and in lint findings.
	ASN1Name string
	// ShortName is the RFC 4519 abbreviation used in string-encoded DNs
	// (for example `CN`). Empty when the attribute has no standard
	// abbreviation.
	ShortName string
	// DisplayName is the human-readable name of the attribute.
	DisplayName string
	// OID is the dotted-decimal object identifier of the attribute type.
	OID string
}

// SubjectAttributeInfo maps profile subject attribute keys to their metadata.
// The canonical key is the snake_case form of the X.520 attribute name, so
// `stateOrProvinceName` is written `state_or_province_name`. Shorter spellings
// are accepted as aliases; see subjectAttributeAliases.
//
// Any attribute type present in a certificate but absent from a profile's
// attribute list is reported as a violation, so this registry also provides the
// names used in those messages.
var SubjectAttributeInfo = map[string]SubjectAttributeMeta{
	"common_name":                         {"commonName", "CN", "Common Name", "2.5.4.3"},
	"surname":                             {"surname", "SN", "Surname", "2.5.4.4"},
	"serial_number":                       {"serialNumber", "", "Serial Number", "2.5.4.5"},
	"country_name":                        {"countryName", "C", "Country", "2.5.4.6"},
	"locality_name":                       {"localityName", "L", "Locality", "2.5.4.7"},
	"state_or_province_name":              {"stateOrProvinceName", "ST", "State or Province", "2.5.4.8"},
	"street_address":                      {"streetAddress", "STREET", "Street Address", "2.5.4.9"},
	"organization_name":                   {"organizationName", "O", "Organization Name", "2.5.4.10"},
	"organizational_unit_name":            {"organizationalUnitName", "OU", "Organizational Unit", "2.5.4.11"},
	"title":                               {"title", "", "Title", "2.5.4.12"},
	"given_name":                          {"givenName", "GN", "Given Name", "2.5.4.42"},
	"initials":                            {"initials", "", "Initials", "2.5.4.43"},
	"pseudonym":                           {"pseudonym", "", "Pseudonym", "2.5.4.65"},
	"generation_qualifier":                {"generationQualifier", "", "Generation Qualifier", "2.5.4.44"},
	"business_category":                   {"businessCategory", "", "Business Category", "2.5.4.15"},
	"postal_code":                         {"postalCode", "", "Postal Code", "2.5.4.17"},
	"organization_identifier":             {"organizationIdentifier", "", "Organization Identifier", "2.5.4.97"},
	"domain_component":                    {"domainComponent", "DC", "Domain Component", "0.9.2342.19200300.100.1.25"},
	"user_id":                             {"userId", "UID", "User ID", "0.9.2342.19200300.100.1.1"},
	"email_address":                       {"emailAddress", "E", "Email Address", "1.2.840.113549.1.9.1"},
	"jurisdiction_locality_name":          {"jurisdictionLocalityName", "", "Jurisdiction Locality", "1.3.6.1.4.1.311.60.2.1.1"},
	"jurisdiction_state_or_province_name": {"jurisdictionStateOrProvinceName", "", "Jurisdiction State or Province", "1.3.6.1.4.1.311.60.2.1.2"},
	"jurisdiction_country_name":           {"jurisdictionCountryName", "", "Jurisdiction Country", "1.3.6.1.4.1.311.60.2.1.3"},
}

// subjectAttributeAliases maps accepted alternative spellings to the canonical
// key, so that both `locality` and `locality_name` are understood.
var subjectAttributeAliases = map[string]string{
	"country":                 "country_name",
	"locality":                "locality_name",
	"state":                   "state_or_province_name",
	"state_or_province":       "state_or_province_name",
	"province":                "state_or_province_name",
	"organizational_unit":     "organizational_unit_name",
	"organisation_name":       "organization_name",
	"organisation_identifier": "organization_identifier",
	"email":                   "email_address",
	"sur_name":                "surname",
	"family_name":             "surname",
	"given_name":              "given_name",
	"jurisdiction_locality":   "jurisdiction_locality_name",
	"jurisdiction_state":      "jurisdiction_state_or_province_name",
	"jurisdiction_country":    "jurisdiction_country_name",
}

// CanonicalSubjectAttribute resolves a profile key, which may be an alias, to
// its canonical form. The second result reports whether the key is known.
func CanonicalSubjectAttribute(key string) (string, bool) {
	if _, ok := SubjectAttributeInfo[key]; ok {
		return key, true
	}
	if canonical, ok := subjectAttributeAliases[key]; ok {
		return canonical, true
	}
	return key, false
}

// SubjectAttributeLabel returns the X.520 attribute name for a profile key.
// Keys written as raw OIDs are returned unchanged.
func SubjectAttributeLabel(key string) string {
	canonical, known := CanonicalSubjectAttribute(key)
	if !known {
		return key
	}
	return SubjectAttributeInfo[canonical].ASN1Name
}

// SubjectAttributeMetaFor returns the metadata for a profile key, resolving
// aliases. The second result reports whether the key is known.
func SubjectAttributeMetaFor(key string) (SubjectAttributeMeta, bool) {
	canonical, known := CanonicalSubjectAttribute(key)
	if !known {
		return SubjectAttributeMeta{}, false
	}
	return SubjectAttributeInfo[canonical], true
}

// ValidatedSubjectFields is the set of subject attribute names understood by
// the tools, including the accepted aliases.
var ValidatedSubjectFields = func() map[string]bool {
	m := make(map[string]bool, len(SubjectAttributeInfo)+len(subjectAttributeAliases))
	for name := range SubjectAttributeInfo {
		m[name] = true
	}
	for alias := range subjectAttributeAliases {
		m[alias] = true
	}
	return m
}()

// SubjectAttributeOID resolves a subject attribute entry to its OID. Entries
// may be written as one of the well-known names above, one of their aliases,
// or as a raw OID.
func SubjectAttributeOID(value string) (string, bool) {
	if info, ok := SubjectAttributeMetaFor(value); ok {
		return info.OID, true
	}
	if IsValidOID(value) {
		return value, true
	}
	return "", false
}

// SubjectAttributeName returns the canonical profile key for a subject
// attribute OID, or an empty string when the OID is not one of the well-known
// attributes.
func SubjectAttributeName(oid string) string {
	for name, info := range SubjectAttributeInfo {
		if info.OID == oid {
			return name
		}
	}
	return ""
}

// IsSupportedSubjectAttribute reports whether an attribute key can be
// interpreted, either as a well-known name or as a raw OID.
func IsSupportedSubjectAttribute(name string) bool {
	_, ok := SubjectAttributeOID(name)
	return ok
}

// IsSupportedExtension reports whether an extension key can be interpreted,
// either as a well-known name, as a raw OID, or as a key registered by a
// profile through `extension_oid`.
func IsSupportedExtension(name string) bool {
	if _, ok := ExtensionInfo[name]; ok {
		return true
	}
	if _, ok := customExtensionOID(name); ok {
		return true
	}
	return IsValidOID(name)
}

// customExtensionOIDs records extension keys declared by profiles through
// `extension_oid`, so that an extension that is not well known can still be
// named readably and resolved to an OID everywhere else in the program.
var customExtensionOIDs = map[string]string{}

// customExtensionOID looks up a profile-declared extension key.
func customExtensionOID(name string) (string, bool) {
	oid, ok := customExtensionOIDs[name]
	return oid, ok
}

// RegisterExtension records the OID of an extension that is not one of the
// well-known extensions. Registering the same key with the same OID is
// harmless; registering it with a different OID, or shadowing a well-known
// extension, is an error.
func RegisterExtension(name, oid string) error {
	if !IsValidOID(oid) {
		return fmt.Errorf("extension %q declares extension_oid %q, which is not a valid OID", name, oid)
	}
	if info, ok := ExtensionInfo[name]; ok {
		if info.OID != oid {
			return fmt.Errorf(
				"extension %q is a well-known extension with OID %s and cannot be redeclared as %s",
				name, info.OID, oid)
		}
		return nil
	}
	if existing, ok := customExtensionOIDs[name]; ok && existing != oid {
		return fmt.Errorf(
			"extension %q is already declared with OID %s and cannot be redeclared as %s",
			name, existing, oid)
	}
	customExtensionOIDs[name] = oid
	return nil
}

// ExtensionMeta describes an extension for documentation purposes.
type ExtensionMeta struct {
	// DisplayName is the RFC 5280 name of the extension.
	DisplayName string
	// OID is the dotted-decimal object identifier of the extension.
	OID string
	// Description explains the purpose of the extension.
	Description string
	// ValueLabel names the entries of the required/optional lists.
	ValueLabel string
}

// ExtensionInfo maps profile extension keys to their documentation metadata.
var ExtensionInfo = map[string]ExtensionMeta{
	"basic_constraints": {
		DisplayName: "Basic Constraints",
		OID:         "2.5.29.19",
		Description: "Indicates whether the subject of the certificate is a CA and, when it is, how deep a certification path may be.",
	},
	"key_usage": {
		DisplayName: "Key Usage",
		OID:         "2.5.29.15",
		Description: "Defines the cryptographic operations for which the public key contained in the certificate may be used.",
		ValueLabel:  "Key Usage",
	},
	"extended_key_usage": {
		DisplayName: "Extended Key Usage",
		OID:         "2.5.29.37",
		Description: "Defines the application purposes for which the certified public key may be used, in addition to or in place of the basic Key Usage.",
		ValueLabel:  "Purpose",
	},
	"subject_alt_name": {
		DisplayName: "Subject Alternative Name",
		OID:         "2.5.29.17",
		Description: "Binds additional identities, such as DNS names and IP addresses, to the subject of the certificate.",
		ValueLabel:  "Name Type",
	},
	"issuer_alt_name": {
		DisplayName: "Issuer Alternative Name",
		OID:         "2.5.29.18",
		Description: "Binds additional identities to the issuer of the certificate.",
		ValueLabel:  "Name Type",
	},
	"authority_key_identifier": {
		DisplayName: "Authority Key Identifier",
		OID:         "2.5.29.35",
		Description: "Identifies the public key corresponding to the private key used to sign the certificate.",
	},
	"subject_key_identifier": {
		DisplayName: "Subject Key Identifier",
		OID:         "2.5.29.14",
		Description: "Identifies the public key contained in the certificate.",
	},
	"certificate_policies": {
		DisplayName: "Certificate Policies",
		OID:         "2.5.29.32",
		Description: "Lists the certificate policies under which the certificate has been issued.",
		ValueLabel:  "Policy",
	},
	"policy_mappings": {
		DisplayName: "Policy Mappings",
		OID:         "2.5.29.33",
		Description: "Indicates equivalence between policies of the issuing and subject CA domains.",
	},
	"policy_constraints": {
		DisplayName: "Policy Constraints",
		OID:         "2.5.29.36",
		Description: "Constrains path validation by requiring explicit policies or inhibiting policy mapping.",
	},
	"name_constraints": {
		DisplayName: "Name Constraints",
		OID:         "2.5.29.30",
		Description: "Constrains the name space within which all subject names in subsequent certificates must be located.",
	},
	"inhibit_any_policy": {
		DisplayName: "Inhibit anyPolicy",
		OID:         "2.5.29.54",
		Description: "Indicates that the anyPolicy policy identifier is no longer permitted.",
	},
	"crl_distribution_points": {
		DisplayName: "CRL Distribution Points",
		OID:         "2.5.29.31",
		Description: "Identifies how certificate revocation list information is obtained.",
	},
	"freshest_crl": {
		DisplayName: "Freshest CRL",
		OID:         "2.5.29.46",
		Description: "Identifies how delta CRL information is obtained.",
	},
	"subject_directory_attributes": {
		DisplayName: "Subject Directory Attributes",
		OID:         "2.5.29.9",
		Description: "Conveys identification attributes of the subject.",
	},
	"authority_information_access": {
		DisplayName: "Authority Information Access",
		OID:         "1.3.6.1.5.5.7.1.1",
		Description: "Indicates how to access information and services of the issuer, such as OCSP responders and issuer certificates.",
	},
	"subject_information_access": {
		DisplayName: "Subject Information Access",
		OID:         "1.3.6.1.5.5.7.1.11",
		Description: "Indicates how to access information and services of the subject.",
	},
	"qc_statements": {
		DisplayName: "qcStatements",
		OID:         "1.3.6.1.5.5.7.1.3",
		Description: "Declares that the certificate is a qualified certificate and conveys related statements.",
	},
	"tls_feature": {
		DisplayName: "TLS Feature",
		OID:         "1.3.6.1.5.5.7.1.24",
		Description: "Lists TLS features that must be supported, such as OCSP status request (must-staple).",
	},
	"ocsp_nocheck": {
		DisplayName: "OCSP No Check",
		OID:         "1.3.6.1.5.5.7.48.1.5",
		Description: "Indicates that an OCSP responder certificate need not have its own revocation status checked.",
	},
	"signed_certificate_timestamps": {
		DisplayName: "Signed Certificate Timestamp List",
		OID:         "1.3.6.1.4.1.11129.2.4.2",
		Description: "Carries Signed Certificate Timestamps proving submission to Certificate Transparency logs.",
	},
	"precertificate_poison": {
		DisplayName: "Precertificate Poison",
		OID:         "1.3.6.1.4.1.11129.2.4.3",
		Description: "Marks a Precertificate so that it will not be accepted as a certificate by relying parties.",
	},
	"cabf_organization_identifier": {
		DisplayName: "CA/Browser Forum Organization Identifier",
		OID:         "2.23.140.3.1",
		Description: "Conveys the registration scheme, country, optional state or province and registration reference of the subject organization, as defined by the CA/Browser Forum.",
	},
}

// ExtensionOID resolves an extension key to its OID. Keys may be written as
// one of the well-known names above or as a raw OID.
func ExtensionOID(key string) (string, bool) {
	if info, ok := ExtensionInfo[key]; ok {
		return info.OID, true
	}
	if oid, ok := customExtensionOID(key); ok {
		return oid, true
	}
	if IsValidOID(key) {
		return key, true
	}
	return "", false
}

// ExtensionName returns the profile key for an extension OID, or an empty
// string when the OID is not one of the well-known extensions.
func ExtensionName(oid string) string {
	for name, info := range ExtensionInfo {
		if info.OID == oid {
			return name
		}
	}
	for name, o := range customExtensionOIDs {
		if o == oid {
			return name
		}
	}
	return ""
}

// ExtensionMetaFor returns documentation metadata for an extension key,
// falling back to a profile-declared OID for extensions that are not well
// known.
func ExtensionMetaFor(key string) ExtensionMeta {
	if info, ok := ExtensionInfo[key]; ok {
		return info
	}
	if oid, ok := ExtensionOID(key); ok {
		return ExtensionMeta{OID: oid}
	}
	return ExtensionMeta{}
}

// AccessMethodMeta documents an information access method.
type AccessMethodMeta struct {
	// OID is the dotted-decimal object identifier of the access method.
	OID string
	// DisplayName is the human-readable name of the access method.
	DisplayName string
	// Description explains what the access location provides.
	Description string
}

// AccessMethodInfo maps access method names to their metadata. These are the
// values accepted by `access_descriptions[].access_method`.
var AccessMethodInfo = map[string]AccessMethodMeta{
	"id-ad-ocsp": {
		OID:         "1.3.6.1.5.5.7.48.1",
		DisplayName: "OCSP",
		Description: "Location of the OCSP responder for revocation status of this certificate",
	},
	"id-ad-caIssuers": {
		OID:         "1.3.6.1.5.5.7.48.2",
		DisplayName: "CA Issuers",
		Description: "Location of certificates issued to the issuer of this certificate",
	},
	"id-ad-timeStamping": {
		OID:         "1.3.6.1.5.5.7.48.3",
		DisplayName: "Time Stamping",
		Description: "Location of the time stamping service offered by the subject",
	},
	"id-ad-caRepository": {
		OID:         "1.3.6.1.5.5.7.48.5",
		DisplayName: "CA Repository",
		Description: "Location of the repository of certificates issued by the subject",
	},
}

// AccessMethodOID resolves an access method entry to its OID. Entries may be
// written as one of the well-known names above or as a raw OID.
func AccessMethodOID(value string) (string, bool) {
	if info, ok := AccessMethodInfo[value]; ok {
		return info.OID, true
	}
	if IsValidOID(value) {
		return value, true
	}
	return "", false
}

// AccessMethodName returns the well-known name for an access method OID, or an
// empty string when the OID is not one of the well-known methods.
func AccessMethodName(oid string) string {
	for name, info := range AccessMethodInfo {
		if info.OID == oid {
			return name
		}
	}
	return ""
}

// SupportsAccessDescriptions reports whether an extension carries a sequence of
// AccessDescription entries.
func SupportsAccessDescriptions(extName string) bool {
	oid, ok := ExtensionOID(extName)
	if !ok {
		return false
	}
	// Authority Information Access and Subject Information Access.
	return oid == "1.3.6.1.5.5.7.1.1" || oid == "1.3.6.1.5.5.7.1.11"
}

// ArcWildcardSuffix is the suffix that marks an OID arc in a profile.
const ArcWildcardSuffix = ".*"

// ArcPrefix validates an arc such as `1.3.6.1.4.1.6449.*` and returns the OID
// prefix without the wildcard. The second result reports whether the arc is
// well formed.
func ArcPrefix(arc string) (string, bool) {
	if !strings.HasSuffix(arc, ArcWildcardSuffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(arc, ArcWildcardSuffix)
	if !IsValidOID(prefix) {
		return "", false
	}
	return prefix, true
}

// OIDInArc reports whether oid is the arc prefix itself or lies beneath it.
// Matching is done on whole arc components, so `1.3.6.1.4.1.64491` does not
// fall under the arc `1.3.6.1.4.1.6449.*`.
func OIDInArc(oid, arc string) bool {
	prefix, ok := ArcPrefix(arc)
	if !ok {
		return false
	}
	return oid == prefix || strings.HasPrefix(oid, prefix+".")
}

// MatchingArc returns the first arc in arcs that oid falls under, or an empty
// string when it falls under none.
func MatchingArc(oid string, arcs []string) string {
	for _, arc := range arcs {
		if OIDInArc(oid, arc) {
			return arc
		}
	}
	return ""
}

// SupportsValueArcs reports whether an extension's values are OIDs, and so can
// be constrained by arc.
func SupportsValueArcs(extName string) bool {
	oid, ok := ExtensionOID(extName)
	if !ok {
		return false
	}
	// Certificate Policies and Extended Key Usage both carry OID values.
	return oid == CertificatePoliciesOID || oid == ExtendedKeyUsageOID
}

// Well-known extension OIDs used when an extension's behaviour depends on
// which extension it is, so that profiles may key it by name or by OID.
const (
	KeyUsageOID              = "2.5.29.15"
	SubjectAltNameOID        = "2.5.29.17"
	IssuerAltNameOID         = "2.5.29.18"
	CRLDistributionPointsOID = "2.5.29.31"
	ExtendedKeyUsageOID      = "2.5.29.37"
	FreshestCRLOID           = "2.5.29.46"
)

// SupportsDistributionPoints reports whether an extension carries a sequence of
// DistributionPoint entries.
func SupportsDistributionPoints(extName string) bool {
	oid, ok := ExtensionOID(extName)
	if !ok {
		return false
	}
	return oid == CRLDistributionPointsOID || oid == FreshestCRLOID
}

// GeneralNameMeta describes one alternative of the GeneralName CHOICE of
// RFC 5280.
type GeneralNameMeta struct {
	// ASN1Name is the name of the alternative, for example `dNSName`.
	ASN1Name string
	// Tag is the context-specific tag number of the alternative.
	Tag int
	// Description explains what the name identifies.
	Description string
}

// GeneralNameInfo maps profile keys to the GeneralName alternatives. The
// canonical key is the snake_case form of the ASN.1 name, matching the
// convention used for subject attributes.
var GeneralNameInfo = map[string]GeneralNameMeta{
	"other_name":                  {"otherName", 0, "A name of a type defined by an accompanying OID"},
	"rfc822_name":                 {"rfc822Name", 1, "An Internet electronic mail address"},
	"dns_name":                    {"dNSName", 2, "A fully qualified domain name"},
	"x400_address":                {"x400Address", 3, "An X.400 originator or recipient address"},
	"directory_name":              {"directoryName", 4, "An X.500 distinguished name"},
	"edi_party_name":              {"ediPartyName", 5, "A name within an EDI trading partner community"},
	"uniform_resource_identifier": {"uniformResourceIdentifier", 6, "A URI naming the subject"},
	"ip_address":                  {"iPAddress", 7, "An IPv4 or IPv6 address"},
	"registered_id":               {"registeredID", 8, "An identifier registered as an OID"},
}

// generalNameAliases maps accepted alternative spellings to the canonical key.
var generalNameAliases = map[string]string{
	"dns":           "dns_name",
	"email":         "rfc822_name",
	"email_address": "rfc822_name",
	"ip":            "ip_address",
	"uri":           "uniform_resource_identifier",
	"url":           "uniform_resource_identifier",
}

// CanonicalGeneralName resolves a profile key, which may be an alias, to its
// canonical form. The second result reports whether the key is known.
func CanonicalGeneralName(key string) (string, bool) {
	if _, ok := GeneralNameInfo[key]; ok {
		return key, true
	}
	if canonical, ok := generalNameAliases[key]; ok {
		return canonical, true
	}
	return key, false
}

// GeneralNameTag resolves a general name entry to its context-specific tag.
func GeneralNameTag(key string) (int, bool) {
	canonical, ok := CanonicalGeneralName(key)
	if !ok {
		return 0, false
	}
	return GeneralNameInfo[canonical].Tag, true
}

// GeneralNameByTag returns the canonical profile key for a context-specific
// tag, or an empty string when the tag is not one of the known alternatives.
func GeneralNameByTag(tag int) string {
	for name, info := range GeneralNameInfo {
		if info.Tag == tag {
			return name
		}
	}
	return ""
}

// GeneralNameLabel returns the ASN.1 name for a profile key, resolving aliases.
func GeneralNameLabel(key string) string {
	canonical, ok := CanonicalGeneralName(key)
	if !ok {
		return key
	}
	return GeneralNameInfo[canonical].ASN1Name
}

// GeneralNameMetaFor returns the metadata for a profile key, resolving aliases.
func GeneralNameMetaFor(key string) (GeneralNameMeta, bool) {
	canonical, ok := CanonicalGeneralName(key)
	if !ok {
		return GeneralNameMeta{}, false
	}
	return GeneralNameInfo[canonical], true
}

// SupportsGeneralNames reports whether an extension carries a GeneralNames
// sequence, and so is constrained by name type rather than by OID.
func SupportsGeneralNames(extName string) bool {
	oid, ok := ExtensionOID(extName)
	if !ok {
		return false
	}
	return oid == SubjectAltNameOID || oid == IssuerAltNameOID
}

// PolicyMeta documents a certificate policy identifier.
type PolicyMeta struct {
	// OID is the dotted-decimal policy identifier.
	OID string
	// Description explains what the policy asserts.
	Description string
}

// PolicyInfo maps well-known certificate policy names to their metadata. These
// are the values accepted by certificate_policies required_values and
// optional_values, alongside raw OIDs.
var PolicyInfo = map[string]PolicyMeta{
	"domain-validated": {
		OID:         "2.23.140.1.2.1",
		Description: "CA/Browser Forum Baseline Requirements, domain validated",
	},
	"organization-validated": {
		OID:         "2.23.140.1.2.2",
		Description: "CA/Browser Forum Baseline Requirements, organization validated",
	},
	"individual-validated": {
		OID:         "2.23.140.1.2.3",
		Description: "CA/Browser Forum Baseline Requirements, individual validated",
	},
	"extended-validation": {
		OID:         "2.23.140.1.1",
		Description: "CA/Browser Forum Extended Validation Guidelines",
	},
	"any-policy": {
		OID:         "2.5.29.32.0",
		Description: "The anyPolicy identifier of RFC 5280",
	},
}

// PolicyOID resolves a certificate policy entry to its OID. Entries may be
// written as one of the well-known names above or as a raw OID.
func PolicyOID(value string) (string, bool) {
	if info, ok := PolicyInfo[value]; ok {
		return info.OID, true
	}
	if IsValidOID(value) {
		return value, true
	}
	return "", false
}

// PolicyName returns the well-known name for a policy OID, or an empty string
// when the OID is not one of the well-known policies.
func PolicyName(oid string) string {
	for name, info := range PolicyInfo {
		if info.OID == oid {
			return name
		}
	}
	return ""
}

// CertificatePoliciesOID is the OID of the Certificate Policies extension.
const CertificatePoliciesOID = "2.5.29.32"

// ExtKeyUsageInfo documents each supported extended key usage value.
var ExtKeyUsageInfo = map[string]struct{ OID, Description string }{
	"serverAuth":      {"1.3.6.1.5.5.7.3.1", "TLS server authentication"},
	"clientAuth":      {"1.3.6.1.5.5.7.3.2", "TLS client authentication"},
	"codeSigning":     {"1.3.6.1.5.5.7.3.3", "Signing of downloadable executable code"},
	"emailProtection": {"1.3.6.1.5.5.7.3.4", "Email protection (S/MIME)"},
	"timeStamping":    {"1.3.6.1.5.5.7.3.8", "Binding the hash of an object to a time"},
	"OCSPSigning":     {"1.3.6.1.5.5.7.3.9", "Signing of OCSP responses"},
}

// KeyUsageInfo documents each supported key usage value.
var KeyUsageInfo = map[string]string{
	"digitalSignature":  "Verifying digital signatures other than certificate or CRL signatures",
	"contentCommitment": "Non-repudiation; verifying signatures that provide proof of origin",
	"keyEncipherment":   "Enciphering private or secret keys, e.g. key transport",
	"dataEncipherment":  "Directly enciphering raw user data",
	"keyAgreement":      "Use in key agreement schemes",
	"keyCertSign":       "Verifying signatures on public key certificates",
	"cRLSign":           "Verifying signatures on certificate revocation lists",
	"encipherOnly":      "Enciphering data only, during key agreement",
	"decipherOnly":      "Deciphering data only, during key agreement",
}

// ExtKeyUsageOID resolves an extended key usage entry from a profile to its
// dotted-decimal OID. Entries may be written either as one of the well-known
// names in ExtKeyUsageInfo (for example `serverAuth`) or directly as an OID
// (for example `2.16.840.1.113741.1.2.3`).
func ExtKeyUsageOID(value string) (string, bool) {
	if info, ok := ExtKeyUsageInfo[value]; ok {
		return info.OID, true
	}
	if IsValidOID(value) {
		return value, true
	}
	return "", false
}

// ExtKeyUsageName returns the well-known name for an extended key usage OID,
// or an empty string when the OID is not one of the well-known usages.
func ExtKeyUsageName(oid string) string {
	for name, info := range ExtKeyUsageInfo {
		if info.OID == oid {
			return name
		}
	}
	return ""
}

// validateTransparency checks that the Certificate Transparency extension pair
// is described coherently. A Precertificate carries the poison extension and no
// SCTs; the final certificate is the exact opposite, so a profile that mandates
// both unconditionally can never be satisfied.
func validateTransparency(p *Profile) []string {
	var errs []string

	// Resolve the two extensions by OID, so that they are found whether they
	// were listed by name or by raw OID.
	var poison, sct *Extension
	var poisonKey, sctKey string
	for extName := range p.Requirements.Extensions {
		oid, ok := ExtensionOID(extName)
		if !ok {
			continue
		}
		ext := p.Requirements.Extensions[extName]
		switch oid {
		case PrecertificatePoisonOID:
			poison, poisonKey = &ext, extName
		case SCTListOID:
			sct, sctKey = &ext, extName
		}
	}

	if poison != nil {
		// The poison extension exists solely to mark a Precertificate, and
		// RFC 6962 requires it to be critical.
		if poison.Required == PresenceRequired {
			errs = append(errs, fmt.Sprintf(
				"requirements.extensions.%s.required is true, but the poison extension appears only in "+
					"Precertificates; use 'precertificate_only'", poisonKey))
		}
		if poison.Critical != CriticalityRequired {
			errs = append(errs, fmt.Sprintf(
				"requirements.extensions.%s.critical is %s, but RFC 6962 requires the poison extension "+
					"to be critical", poisonKey, poison.Critical.Spelling()))
		}
	}

	if sct != nil && poison != nil {
		// Both listed: they must be described as mutually exclusive.
		if sct.Required == PresenceRequired {
			errs = append(errs, fmt.Sprintf(
				"requirements.extensions.%s.required is true, but a Precertificate carries no SCTs; "+
					"use 'final_only'", sctKey))
		}
	}

	if sct != nil && poison == nil && sct.Required.AppliesToPrecertificates() {
		// The profile distinguishes certificate kinds but never permits the
		// extension that identifies a Precertificate.
		errs = append(errs, fmt.Sprintf(
			"requirements.extensions.%s.required is %s, but requirements.extensions does not list "+
				"'precertificate_poison'; no Precertificate could conform", sctKey, sct.Required.Spelling()))
	}

	return errs
}

// ValidateProfile checks if all fields and extensions in the profile are interpretable.
// It returns a list of error messages for unknown/unsupported fields.
func ValidateProfile(p *Profile) []string {
	var errs []string

	// Check recognized_by
	if oid := p.Profile.RecognizedBy.PolicyOID; oid != "" {
		if !IsValidOID(oid) {
			errs = append(errs, fmt.Sprintf("invalid profile.recognized_by.policy_oid: %q", oid))
		} else {
			// The extension list is exhaustive, so a profile recognized by a
			// policy OID must permit the extension that carries it. Otherwise
			// no certificate could ever conform.
			listed := false
			for extName := range p.Requirements.Extensions {
				if extOID, ok := ExtensionOID(extName); ok && extOID == CertificatePoliciesOID {
					listed = true
					break
				}
			}
			if !listed {
				errs = append(errs, fmt.Sprintf(
					"profile.recognized_by.policy_oid is %s but requirements.extensions does not list "+
						"'certificate_policies'; no certificate could carry the policy OID and still conform", oid))
			}
		}
	}

	// Check subject attributes
	for fieldName := range p.Requirements.Subject.Attributes {
		if !IsSupportedSubjectAttribute(fieldName) {
			errs = append(errs, fmt.Sprintf("unknown subject attribute: %q", fieldName))
		}
	}

	// Check the Certificate Transparency extension pair. A profile that
	// describes Precertificates must permit the poison extension, and the
	// poison extension is only ever correct in a Precertificate.
	errs = append(errs, validateTransparency(p)...)

	// Check extensions
	for extName, ext := range p.Requirements.Extensions {
		if !IsSupportedExtension(extName) {
			errs = append(errs, fmt.Sprintf(
				"unsupported extension: %q; an extension that is not well known must declare its "+
					"object identifier with 'extension_oid'", extName))
			continue
		}

		// The pre-rename spelling wrote values under `required`.
		if ext.legacyRequiredList {
			errs = append(errs, fmt.Sprintf(
				"requirements.extensions.%s.required is a boolean; list values belong under 'required_values'", extName))
		}

		// Arcs are only meaningful where values are OIDs, and each must be a
		// valid OID followed by the wildcard suffix.
		if len(ext.OptionalArcs) > 0 {
			if !SupportsValueArcs(extName) {
				errs = append(errs, fmt.Sprintf(
					"extension %q does not support 'optional_arcs'", extName))
			} else {
				for _, arc := range ext.OptionalArcs {
					if _, ok := ArcPrefix(arc); !ok {
						errs = append(errs, fmt.Sprintf(
							"invalid arc %q in requirements.extensions.%s.optional_arcs; "+
								"an arc must be an OID followed by %q, for example 1.3.6.1.4.1.6449.*",
							arc, extName, ArcWildcardSuffix))
					}
				}
			}
		}

		// Distribution points are only meaningful for the CRL extensions, and
		// each full name entry must name a GeneralName alternative.
		if len(ext.DistributionPoints) > 0 {
			if !SupportsDistributionPoints(extName) {
				errs = append(errs, fmt.Sprintf(
					"extension %q does not support 'distribution_points'", extName))
			} else {
				for i, dp := range ext.DistributionPoints {
					for _, v := range dp.FullName {
						if _, ok := CanonicalGeneralName(v); !ok {
							errs = append(errs, fmt.Sprintf(
								"unknown general name type %q in requirements.extensions.%s.distribution_points[%d].full_name",
								v, extName, i))
						}
					}
					if len(dp.FullName) == 0 && !dp.NameRelativeToCRLIssuer {
						errs = append(errs, fmt.Sprintf(
							"requirements.extensions.%s.distribution_points[%d] describes no distribution point name; "+
								"give 'full_name' or set 'name_relative_to_crl_issuer'", extName, i))
					}
				}
			}
		}

		// Access descriptions are only meaningful for information access
		// extensions, and every access method must be interpretable.
		if len(ext.AccessDescriptions) > 0 {
			if !SupportsAccessDescriptions(extName) {
				errs = append(errs, fmt.Sprintf(
					"extension %q does not support 'access_descriptions'", extName))
			} else {
				seen := map[string]bool{}
				for i, ad := range ext.AccessDescriptions {
					if ad.AccessMethod == "" {
						errs = append(errs, fmt.Sprintf(
							"requirements.extensions.%s.access_descriptions[%d] is missing 'access_method'", extName, i))
						continue
					}
					oid, ok := AccessMethodOID(ad.AccessMethod)
					if !ok {
						errs = append(errs, fmt.Sprintf(
							"unknown access_method %q in requirements.extensions.%s.access_descriptions",
							ad.AccessMethod, extName))
						continue
					}
					if seen[oid] {
						errs = append(errs, fmt.Sprintf(
							"duplicate access_method %q in requirements.extensions.%s.access_descriptions",
							ad.AccessMethod, extName))
					}
					seen[oid] = true
				}
			}
		}

		// valueOK reports whether a required_values/optional_values entry is
		// interpretable for this extension. Resolution is by OID so that an
		// extension keyed by raw OID behaves the same as one keyed by name.
		extOID, _ := ExtensionOID(extName)
		var valueOK func(string) bool
		switch extOID {
		case ExtendedKeyUsageOID:
			// Either a well-known name or a raw dotted-decimal OID.
			valueOK = func(v string) bool {
				_, ok := ExtKeyUsageOID(v)
				return ok
			}
		case KeyUsageOID:
			// Key usages are bits in a BIT STRING; only names are meaningful.
			valueOK = func(v string) bool { return KnownKeyUsages[v] }
		case CertificatePoliciesOID:
			// Either a well-known policy name or a raw dotted-decimal OID.
			valueOK = func(v string) bool {
				_, ok := PolicyOID(v)
				return ok
			}
		case SubjectAltNameOID, IssuerAltNameOID:
			// Values name alternatives of the GeneralName CHOICE.
			valueOK = func(v string) bool {
				_, ok := CanonicalGeneralName(v)
				return ok
			}
		}
		if valueOK != nil {
			for _, list := range []struct {
				key    string
				values []string
			}{{"required_values", ext.RequiredValues}, {"optional_values", ext.OptionalValues}} {
				for _, v := range list.values {
					if !valueOK(v) {
						errs = append(errs, fmt.Sprintf(
							"unknown value %q in requirements.extensions.%s.%s", v, extName, list.key))
					}
				}
			}
		} else if len(ext.RequiredValues) > 0 || len(ext.OptionalValues) > 0 {
			errs = append(errs, fmt.Sprintf(
				"extension %q does not support 'required_values'/'optional_values'", extName))
		}
	}

	return errs
}

// KnownExtKeyUsages lists the extended key usage names understood by the tools.
var KnownExtKeyUsages = map[string]bool{
	"serverAuth":      true,
	"clientAuth":      true,
	"codeSigning":     true,
	"emailProtection": true,
	"timeStamping":    true,
	"OCSPSigning":     true,
}

// KnownKeyUsages lists the key usage names understood by the tools.
var KnownKeyUsages = map[string]bool{
	"digitalSignature":  true,
	"contentCommitment": true,
	"keyEncipherment":   true,
	"dataEncipherment":  true,
	"keyAgreement":      true,
	"keyCertSign":       true,
	"cRLSign":           true,
	"encipherOnly":      true,
	"decipherOnly":      true,
}

// ---------- Strict schema validation (raw YAML keys) ----------

// keys builds a set from the given names.
func keys(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

var (
	topLevelKeys          = keys("profile", "requirements", "rules")
	profileKeys           = keys("name", "version", "recognized_by")
	recognizedByKeys      = keys("policy_oid")
	requirementKeys       = keys("validity", "serial_number", "subject", "extensions")
	validityKeys          = keys("maximum_days")
	serialNumberKeys      = keys("required", "maximum_bit_length", "minimum_octets", "textual_requirement")
	subjectKeys           = keys("required", "allow_empty", "attributes")
	subjectFieldKeys      = keys("required", "length")
	lengthKeys            = keys("min", "max")
	ruleKeys              = keys("id", "text")
	defaultExtensionKeys  = keys("critical", "required")
	accessDescriptionKeys = keys("access_method", "required")
	distributionPointKeys = keys("full_name", "name_relative_to_crl_issuer", "reasons", "crl_issuer", "required")

	extensionKeys = map[string]map[string]bool{
		"basic_constraints":            keys("critical", "required", "ca"),
		"key_usage":                    keys("critical", "required", "required_values", "optional_values"),
		"extended_key_usage":           keys("critical", "required", "required_values", "optional_values", "optional_arcs"),
		"certificate_policies":         keys("critical", "required", "required_values", "optional_values", "optional_arcs"),
		"subject_alt_name":             keys("critical", "required", "required_values", "optional_values"),
		"issuer_alt_name":              keys("critical", "required", "required_values", "optional_values"),
		"authority_information_access": keys("critical", "required", "access_descriptions"),
		"subject_information_access":   keys("critical", "required", "access_descriptions"),
		"crl_distribution_points":      keys("critical", "required", "distribution_points"),
		"freshest_crl":                 keys("critical", "required", "distribution_points"),
	}
)

// allowedExtensionKeys returns the schema for an extension. Extensions without
// a specific schema accept only the generic keys. Every extension may declare
// `extension_oid`, which identifies extensions that are not well known.
func allowedExtensionKeys(name string) map[string]bool {
	base, ok := extensionKeys[name]
	if !ok {
		base = defaultExtensionKeys
	}
	allowed := make(map[string]bool, len(base)+1)
	for k := range base {
		allowed[k] = true
	}
	allowed["extension_oid"] = true
	return allowed
}

// checkKeys reports any key in m that is not part of allowed.
func checkKeys(m map[string]interface{}, allowed map[string]bool, path string) []string {
	var errs []string
	for k := range m {
		if !allowed[k] {
			errs = append(errs, fmt.Sprintf("unrecognized key %q in %s", k, path))
		}
	}
	sort.Strings(errs)
	return errs
}

// asMap returns v as a map when possible.
func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// ValidateRaw walks the raw YAML tree and reports every key the tools do not
// understand, so that unsupported profile content can never be silently ignored.
func ValidateRaw(raw map[string]interface{}) []string {
	var errs []string

	errs = append(errs, checkKeys(raw, topLevelKeys, "root")...)

	if m, ok := asMap(raw["profile"]); ok {
		errs = append(errs, checkKeys(m, profileKeys, "profile")...)
		if rb, ok := asMap(m["recognized_by"]); ok {
			errs = append(errs, checkKeys(rb, recognizedByKeys, "profile.recognized_by")...)
		}
	}

	if req, ok := asMap(raw["requirements"]); ok {
		errs = append(errs, checkKeys(req, requirementKeys, "requirements")...)

		if v, ok := asMap(req["validity"]); ok {
			errs = append(errs, checkKeys(v, validityKeys, "requirements.validity")...)
		}

		if sn, ok := asMap(req["serial_number"]); ok {
			errs = append(errs, checkKeys(sn, serialNumberKeys, "requirements.serial_number")...)
		}

		if subj, ok := asMap(req["subject"]); ok {
			// Detect the older flat layout, where attributes were written
			// directly under requirements.subject, and explain the fix.
			for name := range subj {
				if !subjectKeys[name] && ValidatedSubjectFields[name] {
					errs = append(errs, fmt.Sprintf(
						"subject attribute %q must be nested under requirements.subject.attributes", name))
				}
			}
			errs = append(errs, checkKeys(subj, subjectKeys, "requirements.subject")...)

			if attrs, ok := asMap(subj["attributes"]); ok {
				names := make([]string, 0, len(attrs))
				for name := range attrs {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					f, ok := asMap(attrs[name])
					if !ok {
						continue
					}
					base := "requirements.subject.attributes." + name
					errs = append(errs, checkKeys(f, subjectFieldKeys, base)...)
					if l, ok := asMap(f["length"]); ok {
						errs = append(errs, checkKeys(l, lengthKeys, base+".length")...)
					}
				}
			}
		}

		if exts, ok := asMap(req["extensions"]); ok {
			names := make([]string, 0, len(exts))
			for name := range exts {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				e, ok := asMap(exts[name])
				if !ok {
					continue
				}
				if !IsSupportedExtension(name) {
					// Reported by ValidateProfile as an unsupported extension.
					continue
				}
				// Explain the pre-rename spelling rather than reporting it as
				// a plain unrecognized key.
				if _, hasOptional := e["optional"]; hasOptional {
					errs = append(errs, fmt.Sprintf(
						"requirements.extensions.%s.optional has been renamed to 'optional_values'", name))
					// Reported specifically above; skip the generic message.
					filtered := make(map[string]interface{}, len(e))
					for k, v := range e {
						if k != "optional" {
							filtered[k] = v
						}
					}
					e = filtered
				}
				errs = append(errs, checkKeys(e, allowedExtensionKeys(name), "requirements.extensions."+name)...)

				// Each access description entry is a mapping of its own.
				if ads, ok := e["access_descriptions"].([]interface{}); ok {
					for i, entry := range ads {
						ad, ok := asMap(entry)
						if !ok {
							continue
						}
						errs = append(errs, checkKeys(ad, accessDescriptionKeys,
							fmt.Sprintf("requirements.extensions.%s.access_descriptions[%d]", name, i))...)
					}
				}

				// So is each distribution point entry.
				if dps, ok := e["distribution_points"].([]interface{}); ok {
					for i, entry := range dps {
						dp, ok := asMap(entry)
						if !ok {
							continue
						}
						errs = append(errs, checkKeys(dp, distributionPointKeys,
							fmt.Sprintf("requirements.extensions.%s.distribution_points[%d]", name, i))...)
					}
				}
			}
		}
	}

	if rules, ok := raw["rules"].([]interface{}); ok {
		for i, r := range rules {
			m, ok := asMap(r)
			if !ok {
				continue
			}
			errs = append(errs, checkKeys(m, ruleKeys, fmt.Sprintf("rules[%d]", i))...)
		}
	}

	return errs
}

// Validate combines the structural (raw key) checks with the semantic checks.
// Any returned message means the profile contains something the tools cannot
// interpret and must therefore be treated as a hard error.
func (l *Loaded) Validate() []string {
	errs := ValidateRaw(l.Raw)
	return append(errs, ValidateProfile(&l.Profile)...)
}
