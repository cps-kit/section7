package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolvePath tests the ResolvePath function with various paths.
func TestResolvePath(t *testing.T) {
	data := map[string]interface{}{
		"requirements": map[string]interface{}{
			"validity": map[string]interface{}{
				"maximum_days": 398,
			},
			"subject": map[string]interface{}{
				"organization_name": map[string]interface{}{
					"length": map[string]interface{}{
						"max": 64,
					},
				},
			},
		},
		"profile": map[string]interface{}{
			"name": "TLS OV Certificate",
		},
	}

	tests := []struct {
		path    string
		want    string
		wantOK  bool
		wantKey bool // Whether result should be a map key (human-readable label)
	}{
		{"requirements.validity.maximum_days", "398", true, false},
		{"profile.name", "TLS OV Certificate", true, false},
		{"requirements.subject.organization_name", "organization name", true, true},
		{"nonexistent.path", "", false, false},
		{"requirements.nonexistent", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := ResolvePath(data, tt.path)
			if ok != tt.wantOK {
				t.Errorf("ResolvePath(%q) ok = %v, want %v", tt.path, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("ResolvePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestInterpolateText tests the InterpolateText function.
func TestInterpolateText(t *testing.T) {
	data := map[string]interface{}{
		"requirements": map[string]interface{}{
			"validity": map[string]interface{}{
				"maximum_days": 398,
			},
			"subject": map[string]interface{}{
				"country": map[string]interface{}{},
			},
		},
		"profile": map[string]interface{}{
			"name": "TLS OV Certificate",
		},
	}

	tests := []struct {
		text string
		want string
	}{
		{
			"Maximum validity of {requirements.validity.maximum_days} days",
			"Maximum validity of 398 days",
		},
		{
			"Profile: {profile.name}",
			"Profile: TLS OV Certificate",
		},
		{
			"Subject {requirements.subject.country} field",
			"Subject country field",
		},
		{
			"No placeholders here",
			"No placeholders here",
		},
		{
			"Multiple {profile.name} and {requirements.validity.maximum_days} days",
			"Multiple TLS OV Certificate and 398 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := InterpolateText(tt.text, data)
			if got != tt.want {
				t.Errorf("InterpolateText(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// TestValidateProfileValid tests that valid profiles pass validation.
func TestValidateProfileValid(t *testing.T) {
	validProfile := &Profile{
		Profile: Meta{Name: "Test Profile", Version: 3},
		Requirements: Requirements{
			Validity: Validity{MaximumDays: 398},
			Subject: Subject{
				Required: true,
				Attributes: map[string]Field{
					"common_name":       {Required: true},
					"organization_name": {Required: true},
					"country":           {Required: true},
				},
			},
			Extensions: map[string]Extension{
				"basic_constraints":  {Critical: CriticalityRequired},
				"key_usage":          {Critical: CriticalityRequired},
				"extended_key_usage": {Critical: CriticalityForbidden},
			},
		},
	}

	errs := ValidateProfile(validProfile)
	if len(errs) > 0 {
		t.Errorf("ValidateProfile on valid profile returned errors: %v", errs)
	}
}

// TestValidateProfileInvalidSubjectField tests that unknown subject attributes are detected.
func TestValidateProfileInvalidSubjectField(t *testing.T) {
	invalidProfile := &Profile{
		Profile: Meta{Name: "Bad Profile", Version: 3},
		Requirements: Requirements{
			Validity: Validity{MaximumDays: 398},
			Subject: Subject{
				Required: true,
				Attributes: map[string]Field{
					"common_name":  {Required: true},
					"phone_number": {Required: false}, // UNKNOWN
				},
			},
		},
	}

	errs := ValidateProfile(invalidProfile)
	if len(errs) == 0 {
		t.Fatal("ValidateProfile should have returned errors for unknown subject attribute")
	}

	found := false
	for _, err := range errs {
		if strings.Contains(err, "phone_number") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ValidateProfile errors should mention 'phone_number', got: %v", errs)
	}
}

// TestValidateProfileInvalidExtension tests that unknown extensions are detected.
func TestValidateProfileInvalidExtension(t *testing.T) {
	invalidProfile := &Profile{
		Profile: Meta{Name: "Bad Profile", Version: 3},
		Requirements: Requirements{
			Validity: Validity{MaximumDays: 398},
			Extensions: map[string]Extension{
				"basic_constraints": {Critical: CriticalityRequired},
				"made_up_extension": {Critical: CriticalityForbidden}, // UNKNOWN
			},
		},
	}

	errs := ValidateProfile(invalidProfile)
	if len(errs) == 0 {
		t.Fatal("ValidateProfile should have returned errors for unknown extension")
	}

	found := false
	for _, err := range errs {
		if strings.Contains(err, "made_up_extension") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ValidateProfile errors should mention 'made_up_extension', got: %v", errs)
	}
}

// TestValidateProfileMultipleErrors tests that all errors are reported.
func TestValidateProfileMultipleErrors(t *testing.T) {
	invalidProfile := &Profile{
		Profile: Meta{Name: "Bad Profile", Version: 3},
		Requirements: Requirements{
			Subject: Subject{
				Required: true,
				Attributes: map[string]Field{
					"phone_number":  {Required: false}, // UNKNOWN 1
					"favourite_pet": {Required: false}, // UNKNOWN 2
				},
			},
			Extensions: map[string]Extension{
				"made_up_extension":   {Critical: CriticalityForbidden}, // UNKNOWN 3
				"another_made_up_ext": {Critical: CriticalityForbidden}, // UNKNOWN 4
			},
		},
	}

	errs := ValidateProfile(invalidProfile)
	if len(errs) != 4 {
		t.Errorf("ValidateProfile should return 4 errors, got %d: %v", len(errs), errs)
	}
}

// TestValidateProfileEmptyRequirements tests that empty requirements are valid.
func TestValidateProfileEmptyRequirements(t *testing.T) {
	emptyProfile := &Profile{
		Profile: Meta{Name: "Empty Profile", Version: 3},
		Requirements: Requirements{
			Validity: Validity{MaximumDays: 0},
		},
	}

	errs := ValidateProfile(emptyProfile)
	if len(errs) > 0 {
		t.Errorf("ValidateProfile on empty requirements should not return errors: %v", errs)
	}
}

// ---------- Helpers ----------

// loadYAML writes a profile to a temp file and loads it.
func loadYAML(t *testing.T, yaml string) *Loaded {
	t.Helper()

	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("loading profile: %v", err)
	}
	return loaded
}

// ---------- General names ----------

// TestGeneralNameValuesAccepted verifies SAN value lists are understood.
func TestGeneralNameValuesAccepted(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SAN Values
  version: 3
requirements:
  extensions:
    subject_alt_name:
      required: true
      critical: optional
      required_values:
        - dns_name
      optional_values:
        - ip_address
        - uniform_resource_identifier
`)

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("general name values should be accepted, got: %v", errs)
	}

	san := loaded.Profile.Requirements.Extensions["subject_alt_name"]
	if len(san.RequiredValues) != 1 || san.RequiredValues[0] != "dns_name" {
		t.Errorf("unexpected required_values: %v", san.RequiredValues)
	}
}

// TestGeneralNameAliasesAccepted verifies the short spellings resolve.
func TestGeneralNameAliasesAccepted(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SAN Aliases
  version: 3
requirements:
  extensions:
    subject_alt_name:
      required: true
      optional_values:
        - dns
        - ip
        - uri
        - email
`)

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("alias general names should be accepted, got: %v", errs)
	}

	for alias, canonical := range map[string]string{
		"dns":   "dns_name",
		"ip":    "ip_address",
		"uri":   "uniform_resource_identifier",
		"email": "rfc822_name",
	} {
		aliasTag, ok := GeneralNameTag(alias)
		if !ok {
			t.Errorf("alias %q should resolve", alias)
			continue
		}
		canonicalTag, _ := GeneralNameTag(canonical)
		if aliasTag != canonicalTag {
			t.Errorf("alias %q resolved to tag %d, want %d", alias, aliasTag, canonicalTag)
		}
	}
}

// TestGeneralNameUnknownRejected verifies an unknown name type is reported.
func TestGeneralNameUnknownRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SAN Bad Value
  version: 3
requirements:
  extensions:
    subject_alt_name:
      required: true
      optional_values:
        - telephone_number
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "telephone_number") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unknown general name type should be reported, got: %v", errs)
	}
}

// TestGeneralNameTagsAreCorrect guards the context-specific tag numbers, which
// are what the linter matches against.
func TestGeneralNameTagsAreCorrect(t *testing.T) {
	want := map[string]int{
		"other_name":                  0,
		"rfc822_name":                 1,
		"dns_name":                    2,
		"x400_address":                3,
		"directory_name":              4,
		"edi_party_name":              5,
		"uniform_resource_identifier": 6,
		"ip_address":                  7,
		"registered_id":               8,
	}

	for name, tag := range want {
		got, ok := GeneralNameTag(name)
		if !ok {
			t.Errorf("%s should be a known general name", name)
			continue
		}
		if got != tag {
			t.Errorf("%s tag = %d, want %d", name, got, tag)
		}
		if GeneralNameByTag(tag) != name {
			t.Errorf("tag %d maps to %q, want %q", tag, GeneralNameByTag(tag), name)
		}
	}
}

// TestGeneralNameValuesRejectedElsewhere verifies name types are only accepted
// on extensions that carry GeneralNames.
func TestGeneralNameValuesRejectedElsewhere(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SAN Wrong Place
  version: 3
requirements:
  extensions:
    basic_constraints:
      required: true
      optional_values:
        - dns_name
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "required_values") || strings.Contains(err, "optional_values") {
			found = true
		}
	}
	if !found {
		t.Errorf("basic_constraints should not accept name types, got: %v", errs)
	}
}

// ---------- Certificate Transparency ----------

// TestPresenceParsing verifies all four spellings are accepted.
func TestPresenceParsing(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Presence
  version: 3
requirements:
  extensions:
    basic_constraints:
      required: true
    subject_key_identifier:
      required: false
    signed_certificate_timestamps:
      required: final_only
    precertificate_poison:
      required: precertificate_only
      critical: true
`)

	exts := loaded.Profile.Requirements.Extensions

	cases := map[string]Presence{
		"basic_constraints":             PresenceRequired,
		"subject_key_identifier":        PresenceOptional,
		"signed_certificate_timestamps": PresenceFinalOnly,
		"precertificate_poison":         PresencePrecertificateOnly,
	}
	for name, want := range cases {
		if got := exts[name].Required; got != want {
			t.Errorf("%s presence = %v, want %v", name, got.Spelling(), want.Spelling())
		}
	}

	if !loaded.Profile.Requirements.CoversPrecertificates() {
		t.Error("a profile using final_only/precertificate_only covers Precertificates")
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid CT profile should not produce errors: %v", errs)
	}
}

// TestPresenceSemantics verifies the presence rules for both certificate kinds.
func TestPresenceSemantics(t *testing.T) {
	tests := []struct {
		presence      Presence
		isPrecert     bool
		wantRequired  bool
		wantForbidden bool
	}{
		{PresenceRequired, false, true, false},
		{PresenceRequired, true, true, false},
		{PresenceOptional, false, false, false},
		{PresenceOptional, true, false, false},
		{PresenceFinalOnly, false, true, false},
		{PresenceFinalOnly, true, false, true},
		{PresencePrecertificateOnly, false, false, true},
		{PresencePrecertificateOnly, true, true, false},
	}

	for _, tc := range tests {
		if got := tc.presence.RequiredIn(tc.isPrecert); got != tc.wantRequired {
			t.Errorf("%s.RequiredIn(precert=%v) = %v, want %v",
				tc.presence.Spelling(), tc.isPrecert, got, tc.wantRequired)
		}
		if got := tc.presence.ForbiddenIn(tc.isPrecert); got != tc.wantForbidden {
			t.Errorf("%s.ForbiddenIn(precert=%v) = %v, want %v",
				tc.presence.Spelling(), tc.isPrecert, got, tc.wantForbidden)
		}
	}
}

// TestPresenceInvalidValue verifies an uninterpretable spelling is rejected.
func TestPresenceInvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	content := `
profile:
  name: Bad Presence
  version: 3
requirements:
  extensions:
    subject_alt_name:
      required: sometimes
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("an invalid presence value should fail to load")
	}
	if !strings.Contains(err.Error(), "final_only") {
		t.Errorf("error should list the accepted values, got: %v", err)
	}
}

// TestTransparencyPoisonMustBePrecertificateOnly verifies a profile cannot
// mandate the poison extension in every certificate.
func TestTransparencyPoisonMustBePrecertificateOnly(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Poison Always
  version: 3
requirements:
  extensions:
    precertificate_poison:
      required: true
      critical: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "precertificate_only") {
			found = true
		}
	}
	if !found {
		t.Errorf("poison required in every certificate should be reported, got: %v", errs)
	}
}

// TestTransparencyPoisonMustBeCritical verifies RFC 6962's criticality rule.
func TestTransparencyPoisonMustBeCritical(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Poison Not Critical
  version: 3
requirements:
  extensions:
    precertificate_poison:
      required: precertificate_only
      critical: false
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "requires the poison extension") {
			found = true
		}
	}
	if !found {
		t.Errorf("a non-critical poison extension should be reported, got: %v", errs)
	}
}

// TestTransparencySCTsCannotBeUnconditional verifies SCTs cannot be mandated in
// every certificate when Precertificates are also described.
func TestTransparencySCTsCannotBeUnconditional(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SCTs Always
  version: 3
requirements:
  extensions:
    signed_certificate_timestamps:
      required: true
    precertificate_poison:
      required: precertificate_only
      critical: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "final_only") {
			found = true
		}
	}
	if !found {
		t.Errorf("unconditional SCTs alongside poison should be reported, got: %v", errs)
	}
}

// TestTransparencyFinalOnlyNeedsPoison verifies that distinguishing the two
// kinds requires permitting the extension that identifies a Precertificate.
func TestTransparencyFinalOnlyNeedsPoison(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: SCTs Final Only
  version: 3
requirements:
  extensions:
    signed_certificate_timestamps:
      required: final_only
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "precertificate_poison") {
			found = true
		}
	}
	if !found {
		t.Errorf("final_only without poison listed should be reported, got: %v", errs)
	}
}

// ---------- Optional arcs ----------

// TestArcPrefix verifies arc parsing.
func TestArcPrefix(t *testing.T) {
	tests := []struct {
		arc        string
		wantPrefix string
		wantOK     bool
	}{
		{"1.3.6.1.4.1.6449.*", "1.3.6.1.4.1.6449", true},
		{"2.23.140.*", "2.23.140", true},
		{"1.3.6.1.4.1.6449", "", false},     // no wildcard
		{"*", "", false},                    // no prefix
		{".*", "", false},                   // empty prefix
		{"1.3.6.1.4.1.abc.*", "", false},    // not an OID
		{"1.3.6.1.4.1.6449.*.1", "", false}, // wildcard not at the end
	}

	for _, tc := range tests {
		prefix, ok := ArcPrefix(tc.arc)
		if ok != tc.wantOK {
			t.Errorf("ArcPrefix(%q) ok = %v, want %v", tc.arc, ok, tc.wantOK)
			continue
		}
		if prefix != tc.wantPrefix {
			t.Errorf("ArcPrefix(%q) = %q, want %q", tc.arc, prefix, tc.wantPrefix)
		}
	}
}

// TestOIDInArc verifies subordination, including the component boundary.
func TestOIDInArc(t *testing.T) {
	const arc = "1.3.6.1.4.1.6449.*"

	tests := []struct {
		oid  string
		want bool
	}{
		{"1.3.6.1.4.1.6449", true},         // the arc itself
		{"1.3.6.1.4.1.6449.1", true},       // one level below
		{"1.3.6.1.4.1.6449.1.2.2.7", true}, // several levels below
		{"1.3.6.1.4.1.64499", false},       // shares a text prefix, different arc
		{"1.3.6.1.4.1.644", false},         // shorter
		{"2.23.140.1.2.1", false},          // unrelated
	}

	for _, tc := range tests {
		if got := OIDInArc(tc.oid, arc); got != tc.want {
			t.Errorf("OIDInArc(%q, %q) = %v, want %v", tc.oid, arc, got, tc.want)
		}
	}
}

// TestMatchingArc verifies the first matching arc is returned.
func TestMatchingArc(t *testing.T) {
	arcs := []string{"2.23.140.*", "1.3.6.1.4.1.6449.*"}

	if got := MatchingArc("1.3.6.1.4.1.6449.1.2", arcs); got != "1.3.6.1.4.1.6449.*" {
		t.Errorf("MatchingArc returned %q, want the Sectigo arc", got)
	}
	if got := MatchingArc("1.2.3.4", arcs); got != "" {
		t.Errorf("MatchingArc returned %q, want no match", got)
	}
}

// TestOptionalArcsParse verifies arcs are parsed and accepted.
func TestOptionalArcsParse(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Arcs
  recognized_by:
    policy_oid: 2.23.140.1.2.1
  version: 3
requirements:
  extensions:
    certificate_policies:
      required: true
      required_values:
        - 2.23.140.1.2.1
      optional_arcs:
        - 1.3.6.1.4.1.6449.*
`)

	arcs := loaded.Profile.Requirements.Extensions["certificate_policies"].OptionalArcs
	if len(arcs) != 1 || arcs[0] != "1.3.6.1.4.1.6449.*" {
		t.Fatalf("unexpected arcs: %v", arcs)
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid arc profile should not produce errors: %v", errs)
	}
}

// TestOptionalArcsInvalidRejected verifies a malformed arc is reported.
func TestOptionalArcsInvalidRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Bad Arc
  version: 3
requirements:
  extensions:
    certificate_policies:
      required: true
      optional_arcs:
        - 1.3.6.1.4.1.6449
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "invalid arc") {
			found = true
		}
	}
	if !found {
		t.Errorf("an arc without the wildcard suffix should be reported, got: %v", errs)
	}
}

// TestOptionalArcsRejectedOnNonOIDExtension verifies arcs are only accepted
// where values are OIDs.
func TestOptionalArcsRejectedOnNonOIDExtension(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Arc Wrong Place
  version: 3
requirements:
  extensions:
    key_usage:
      required: true
      optional_arcs:
        - 1.3.6.1.4.1.6449.*
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "optional_arcs") {
			found = true
		}
	}
	if !found {
		t.Errorf("key_usage should not accept optional_arcs, got: %v", errs)
	}
}

// ---------- Subject attribute naming ----------

// TestSubjectAttributeCanonicalKeys verifies the canonical key is the
// snake_case form of the X.520 attribute name.
func TestSubjectAttributeCanonicalKeys(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Canonical Keys
  version: 3
requirements:
  subject:
    required: true
    attributes:
      common_name:
        required: true
      country_name:
        required: true
      locality_name:
        required: false
      state_or_province_name:
        required: true
      organizational_unit_name:
        required: false
`)

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("canonical X.520 keys should be accepted, got: %v", errs)
	}
}

// TestSubjectAttributeAliases verifies the shorter spellings still resolve.
func TestSubjectAttributeAliases(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Aliases
  version: 3
requirements:
  subject:
    required: true
    attributes:
      country:
        required: true
      locality:
        required: false
      state:
        required: true
      organizational_unit:
        required: false
`)

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("alias keys should be accepted, got: %v", errs)
	}

	// Aliases resolve to the same OID and label as the canonical key.
	for alias, canonical := range map[string]string{
		"country":             "country_name",
		"locality":            "locality_name",
		"state":               "state_or_province_name",
		"organizational_unit": "organizational_unit_name",
	} {
		aliasOID, ok := SubjectAttributeOID(alias)
		if !ok {
			t.Errorf("alias %q should resolve", alias)
			continue
		}
		canonicalOID, _ := SubjectAttributeOID(canonical)
		if aliasOID != canonicalOID {
			t.Errorf("alias %q resolved to %s, want %s", alias, aliasOID, canonicalOID)
		}
		if SubjectAttributeLabel(alias) != SubjectAttributeLabel(canonical) {
			t.Errorf("alias %q labelled %q, want %q",
				alias, SubjectAttributeLabel(alias), SubjectAttributeLabel(canonical))
		}
	}
}

// TestSubjectAttributeLabelMatchesKey verifies every canonical key is the
// snake_case form of its own ASN.1 name, so the two never drift apart.
func TestSubjectAttributeLabelMatchesKey(t *testing.T) {
	snake := func(s string) string {
		var b strings.Builder
		for i, r := range s {
			if r >= 'A' && r <= 'Z' {
				if i > 0 {
					b.WriteByte('_')
				}
				b.WriteRune(r + ('a' - 'A'))
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}

	for key, info := range SubjectAttributeInfo {
		if got := snake(info.ASN1Name); got != key {
			t.Errorf("key %q should be %q, the snake_case form of %q", key, got, info.ASN1Name)
		}
	}
}

// TestCriticalityParsing verifies all three spellings are accepted.
func TestCriticalityParsing(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Criticality
  version: 3
requirements:
  extensions:
    basic_constraints:
      required: true
      critical: true
    subject_alt_name:
      required: true
      critical: optional
    subject_key_identifier:
      required: true
      critical: false
    authority_key_identifier:
      required: true
`)

	exts := loaded.Profile.Requirements.Extensions

	if got := exts["basic_constraints"].Critical; got != CriticalityRequired {
		t.Errorf("critical: true should parse as CriticalityRequired, got %v", got)
	}
	if got := exts["subject_alt_name"].Critical; got != CriticalityOptional {
		t.Errorf("critical: optional should parse as CriticalityOptional, got %v", got)
	}
	if got := exts["subject_key_identifier"].Critical; got != CriticalityForbidden {
		t.Errorf("critical: false should parse as CriticalityForbidden, got %v", got)
	}
	// Omitted `critical` defaults to forbidden, preserving prior behaviour.
	if got := exts["authority_key_identifier"].Critical; got != CriticalityForbidden {
		t.Errorf("omitted critical should default to CriticalityForbidden, got %v", got)
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid profile should not produce errors: %v", errs)
	}
}

// TestCriticalityAllows verifies the requirement semantics.
func TestCriticalityAllows(t *testing.T) {
	tests := []struct {
		requirement Criticality
		critical    bool
		want        bool
	}{
		{CriticalityRequired, true, true},
		{CriticalityRequired, false, false},
		{CriticalityForbidden, true, false},
		{CriticalityForbidden, false, true},
		{CriticalityOptional, true, true},
		{CriticalityOptional, false, true},
	}

	for _, tc := range tests {
		if got := tc.requirement.Allows(tc.critical); got != tc.want {
			t.Errorf("%v.Allows(%v) = %v, want %v",
				tc.requirement.Spelling(), tc.critical, got, tc.want)
		}
	}
}

// TestCriticalityInvalidValue verifies an uninterpretable value is rejected
// rather than silently treated as false.
func TestCriticalityInvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	content := `
profile:
  name: Bad Criticality
  version: 3
requirements:
  extensions:
    subject_alt_name:
      critical: maybe
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("an invalid criticality value should fail to load")
	}
	if !strings.Contains(err.Error(), "true, false, or optional") {
		t.Errorf("error should explain the accepted values, got: %v", err)
	}
}

// TestAccessDescriptionsParse verifies the list form is parsed.
func TestAccessDescriptionsParse(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: AIA
  version: 3
requirements:
  extensions:
    authority_information_access:
      required: true
      critical: false
      access_descriptions:
        - access_method: id-ad-caIssuers
          required: true
        - access_method: id-ad-ocsp
          required: false
`)

	ads := loaded.Profile.Requirements.Extensions["authority_information_access"].AccessDescriptions
	if len(ads) != 2 {
		t.Fatalf("expected 2 access descriptions, got %d", len(ads))
	}
	if ads[0].AccessMethod != "id-ad-caIssuers" || !ads[0].Required {
		t.Errorf("unexpected first entry: %+v", ads[0])
	}
	if ads[1].AccessMethod != "id-ad-ocsp" || ads[1].Required {
		t.Errorf("unexpected second entry: %+v", ads[1])
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid AIA profile should not produce errors: %v", errs)
	}
}

// TestAccessDescriptionUnknownMethodRejected verifies unknown access methods
// are reported.
func TestAccessDescriptionUnknownMethodRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: AIA Bad Method
  version: 3
requirements:
  extensions:
    authority_information_access:
      required: true
      access_descriptions:
        - access_method: id-ad-teleportation
          required: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "id-ad-teleportation") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unknown access method should be reported, got: %v", errs)
	}
}

// TestAccessDescriptionDuplicateRejected verifies duplicate access methods are
// reported.
func TestAccessDescriptionDuplicateRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: AIA Duplicate
  version: 3
requirements:
  extensions:
    authority_information_access:
      required: true
      access_descriptions:
        - access_method: id-ad-ocsp
          required: true
        - access_method: 1.3.6.1.5.5.7.48.1
          required: false
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "duplicate access_method") {
			found = true
		}
	}
	if !found {
		t.Errorf("a duplicate access method should be reported, got: %v", errs)
	}
}

// TestAccessDescriptionsRejectedOnOtherExtensions verifies access_descriptions
// is only accepted where it is meaningful.
func TestAccessDescriptionsRejectedOnOtherExtensions(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: AIA Wrong Place
  version: 3
requirements:
  extensions:
    key_usage:
      required: true
      access_descriptions:
        - access_method: id-ad-ocsp
          required: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "access_descriptions") {
			found = true
		}
	}
	if !found {
		t.Errorf("key_usage should not accept access_descriptions, got: %v", errs)
	}
}

// TestAccessDescriptionUnknownKeyRejected verifies unknown keys inside an entry
// are reported, which is what the malformed `type:` spelling produces.
func TestAccessDescriptionUnknownKeyRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: AIA Bad Key
  version: 3
requirements:
  extensions:
    authority_information_access:
      required: true
      access_descriptions:
        - access_method: id-ad-ocsp
          type: id-ad-ocsp
          required: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, `unrecognized key "type"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("an unknown key inside an access description should be reported, got: %v", errs)
	}
}

// TestExtensionRequiredIsBoolean verifies the presence flag and renamed value
// lists are parsed.
func TestExtensionRequiredIsBoolean(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Extension Shape
  version: 3
requirements:
  extensions:
    basic_constraints:
      required: true
      critical: true
      ca: false
    extended_key_usage:
      required: false
      critical: false
      required_values:
        - serverAuth
      optional_values:
        - clientAuth
`)

	exts := loaded.Profile.Requirements.Extensions

	bc := exts["basic_constraints"]
	if bc.Required != PresenceRequired {
		t.Error("basic_constraints should be required")
	}
	if bc.Critical != CriticalityRequired {
		t.Error("basic_constraints should be critical")
	}
	if bc.CA == nil || *bc.CA {
		t.Error("basic_constraints ca should be false")
	}

	eku := exts["extended_key_usage"]
	if eku.Required != PresenceOptional {
		t.Error("extended_key_usage should not be required")
	}
	if len(eku.RequiredValues) != 1 || eku.RequiredValues[0] != "serverAuth" {
		t.Errorf("unexpected required_values: %v", eku.RequiredValues)
	}
	if len(eku.OptionalValues) != 1 || eku.OptionalValues[0] != "clientAuth" {
		t.Errorf("unexpected optional_values: %v", eku.OptionalValues)
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid profile should not produce errors: %v", errs)
	}
}

// TestExtensionLegacyRequiredListRejected verifies the pre-rename spelling of
// `required` as a list produces a clear migration message.
func TestExtensionLegacyRequiredListRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Legacy Required
  version: 3
requirements:
  extensions:
    extended_key_usage:
      required:
        - serverAuth
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "required_values") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors should point at 'required_values', got: %v", errs)
	}
}

// TestExtensionLegacyOptionalRejected verifies `optional` is reported as
// renamed rather than as a plain unknown key.
func TestExtensionLegacyOptionalRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Legacy Optional
  version: 3
requirements:
  extensions:
    extended_key_usage:
      required: true
      optional:
        - clientAuth
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "renamed to 'optional_values'") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors should explain the optional_values rename, got: %v", errs)
	}
}

// TestExtensionValuesRejectedOnUnsupportedExtension verifies value lists are
// only accepted where they are meaningful.
func TestExtensionValuesRejectedOnUnsupportedExtension(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Values Where Unsupported
  version: 3
requirements:
  extensions:
    basic_constraints:
      required: true
      required_values:
        - serverAuth
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, "required_values") {
			found = true
		}
	}
	if !found {
		t.Errorf("basic_constraints should not accept value lists, got: %v", errs)
	}
}

// TestSubjectNestedAttributesParse verifies the nested subject layout is parsed.
func TestSubjectNestedAttributesParse(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Nested Subject
  version: 3
requirements:
  subject:
    required: true
    attributes:
      organization_name:
        required: true
        length:
          min: 1
          max: 64
      country:
        required: true
        length:
          min: 2
          max: 2
`)

	subj := loaded.Profile.Requirements.Subject
	if !subj.Required {
		t.Error("requirements.subject.required should have been parsed as true")
	}
	if len(subj.Attributes) != 2 {
		t.Fatalf("expected 2 subject attributes, got %d", len(subj.Attributes))
	}

	country, ok := subj.Attributes["country"]
	if !ok {
		t.Fatal("country attribute was not parsed")
	}
	if !country.Required {
		t.Error("country should be required")
	}
	if country.Length.Min == nil || *country.Length.Min != 2 {
		t.Errorf("country min length should be 2, got %v", country.Length.Min)
	}
	if country.Length.Max == nil || *country.Length.Max != 2 {
		t.Errorf("country max length should be 2, got %v", country.Length.Max)
	}

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Errorf("a valid nested subject profile should not produce errors: %v", errs)
	}
}

// TestSubjectFlatLayoutRejected verifies the older flat layout produces a clear
// migration message rather than being silently ignored.
func TestSubjectFlatLayoutRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Flat Subject
  version: 3
requirements:
  subject:
    organization_name:
      required: true
`)

	errs := loaded.Validate()
	if len(errs) == 0 {
		t.Fatal("the flat subject layout should be rejected")
	}

	found := false
	for _, err := range errs {
		if strings.Contains(err, "must be nested under requirements.subject.attributes") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("errors should explain the required nesting, got: %v", errs)
	}
}

// TestSubjectUnknownKeyRejected verifies unknown keys under subject are caught.
func TestSubjectUnknownKeyRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Bad Subject Key
  version: 3
requirements:
  subject:
    required: true
    bogus: 1
    attributes:
      country:
        required: true
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, `unrecognized key "bogus" in requirements.subject`) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("an unknown key under subject should be reported, got: %v", errs)
	}
}

// TestSubjectUnknownAttributeKeyRejected verifies unknown keys inside an
// attribute are caught at the new, deeper path.
func TestSubjectUnknownAttributeKeyRejected(t *testing.T) {
	loaded := loadYAML(t, `
profile:
  name: Bad Attribute Key
  version: 3
requirements:
  subject:
    required: true
    attributes:
      country:
        required: true
        bogus: 1
`)

	errs := loaded.Validate()
	found := false
	for _, err := range errs {
		if strings.Contains(err, `unrecognized key "bogus" in requirements.subject.attributes.country`) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("an unknown key inside an attribute should be reported, got: %v", errs)
	}
}

// ---------- Inheritance ----------

// loadFiles writes several profile files to one directory and loads entry.
func loadFiles(t *testing.T, entry string, files map[string]string) *Loaded {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	loaded, err := Load(filepath.Join(dir, entry))
	if err != nil {
		t.Fatalf("loading %s: %v", entry, err)
	}
	return loaded
}

// TestExtendsInheritsAndOverrides verifies a profile inherits what a base
// defines, adds to it, and wins wherever the two disagree.
func TestExtendsInheritsAndOverrides(t *testing.T) {
	loaded := loadFiles(t, "child.yaml", map[string]string{
		"_base.yaml": `
requirements:
  validity:
    maximum_days: 398
  subject:
    required: true
    attributes:
      country_name:
        required: true
  extensions:
    basic_constraints:
      required: true
      critical: true
      ca: false
`,
		"child.yaml": `
extends: _base.yaml
profile:
  name: Child
  version: 3
requirements:
  validity:
    maximum_days: 200
  subject:
    attributes:
      common_name:
        required: false
  extensions:
    key_usage:
      required: true
      critical: true
      required_values:
        - digitalSignature
`,
	})

	if errs := loaded.Validate(); len(errs) > 0 {
		t.Fatalf("an inherited profile should validate, got: %v", errs)
	}

	req := loaded.Profile.Requirements
	if req.Validity.MaximumDays != 200 {
		t.Errorf("the profile should override the inherited validity, got %d", req.Validity.MaximumDays)
	}
	if !req.Subject.Required {
		t.Error("subject.required should be inherited from the base")
	}
	for _, attr := range []string{"country_name", "common_name"} {
		if _, ok := req.Subject.Attributes[attr]; !ok {
			t.Errorf("attribute %q should be present after merging", attr)
		}
	}
	for _, ext := range []string{"basic_constraints", "key_usage"} {
		if _, ok := req.Extensions[ext]; !ok {
			t.Errorf("extension %q should be present after merging", ext)
		}
	}
}

// TestExtendsReplacesSequences verifies a profile narrows an inherited list by
// restating it, rather than being stuck with the union of the two.
func TestExtendsReplacesSequences(t *testing.T) {
	loaded := loadFiles(t, "child.yaml", map[string]string{
		"_base.yaml": `
requirements:
  extensions:
    extended_key_usage:
      required: true
      required_values:
        - emailProtection
      optional_values:
        - clientAuth
`,
		"child.yaml": `
extends: _base.yaml
profile:
  name: Strict Child
  version: 3
requirements:
  extensions:
    extended_key_usage:
      optional_values: []
`,
	})

	eku := loaded.Profile.Requirements.Extensions["extended_key_usage"]
	if len(eku.OptionalValues) != 0 {
		t.Errorf("the profile should have replaced the inherited list, got: %v", eku.OptionalValues)
	}
	if len(eku.RequiredValues) != 1 || eku.RequiredValues[0] != "emailProtection" {
		t.Errorf("untouched lists should be inherited, got: %v", eku.RequiredValues)
	}
}

// TestExtendsMergesInOrder verifies that later entries win over earlier ones,
// and that the profile itself wins over all of them.
func TestExtendsMergesInOrder(t *testing.T) {
	loaded := loadFiles(t, "child.yaml", map[string]string{
		"_first.yaml": `
requirements:
  validity:
    maximum_days: 100
  subject:
    attributes:
      country_name:
        required: true
`,
		"_second.yaml": `
requirements:
  validity:
    maximum_days: 200
  subject:
    attributes:
      common_name:
        required: false
`,
		"child.yaml": `
extends:
  - _first.yaml
  - _second.yaml
profile:
  name: Mixed
  version: 3
`,
	})

	req := loaded.Profile.Requirements
	if req.Validity.MaximumDays != 200 {
		t.Errorf("the last base listed should win, got %d", req.Validity.MaximumDays)
	}
	if len(req.Subject.Attributes) != 2 {
		t.Errorf("attributes from both bases should be present, got: %v", req.Subject.Attributes)
	}
}

// TestExtendsCycleReported verifies an inheritance cycle is an error rather
// than a hang.
func TestExtendsCycleReported(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"a.yaml": "extends: b.yaml\n",
		"b.yaml": "extends: a.yaml\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	if _, err := Load(filepath.Join(dir, "a.yaml")); err == nil {
		t.Fatal("a cycle should be reported")
	} else if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("the error should name the cycle, got: %v", err)
	}
}

// TestLoadDirSkipsFragments verifies that the shared definition files profiles
// inherit from are not themselves treated as profiles.
func TestLoadDirSkipsFragments(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"_base.yaml": "requirements:\n  validity:\n    maximum_days: 200\n",
		"leaf.yaml":  "extends: _base.yaml\nprofile:\n  name: Leaf\n  version: 3\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	profiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("loading directory: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("only the leaf profile should be discovered, got %d", len(profiles))
	}
	if _, ok := profiles[filepath.Join(dir, "leaf.yaml")]; !ok {
		t.Errorf("the leaf profile should be discovered, got: %v", profiles)
	}
}
