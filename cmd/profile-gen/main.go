package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"section7/internal/profile"
)

func boolStr(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// dash renders an empty string as a table placeholder.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// humanize turns a snake_case profile key into a space separated label.
func humanize(s string) string {
	return strings.Join(strings.Split(s, "_"), " ")
}

// extLabel returns the documented display name of an extension, falling back
// to a humanized version of the profile key.
func extLabel(name string) string {
	if meta, ok := profile.ExtensionInfo[name]; ok && meta.DisplayName != "" {
		return meta.DisplayName
	}
	return humanize(name)
}

// criticalSentence describes the presence and criticality requirements in prose.
func criticalSentence(label string, required profile.Presence, critical profile.Criticality) string {
	var criticality string
	switch critical {
	case profile.CriticalityRequired:
		criticality = "MUST be marked critical"
	case profile.CriticalityOptional:
		criticality = "MAY be marked critical"
	default:
		criticality = "MUST NOT be marked critical"
	}

	switch required {
	case profile.PresenceRequired:
		return fmt.Sprintf("The %s extension MUST be present and %s.\n\n", label, criticality)
	case profile.PresenceFinalOnly:
		return fmt.Sprintf(
			"The %s extension MUST be present in final certificates and %s. "+
				"It MUST NOT be present in Precertificates.\n\n", label, criticality)
	case profile.PresencePrecertificateOnly:
		return fmt.Sprintf(
			"The %s extension MUST be present in Precertificates and %s. "+
				"It MUST NOT be present in final certificates.\n\n", label, criticality)
	default:
		return fmt.Sprintf("The %s extension MAY be present. When present, it %s.\n\n", label, criticality)
	}
}

// renderExtension renders a single extension as its own detailed subsection.
func renderExtension(extName string, ext profile.Extension) string {
	var sb strings.Builder

	meta := profile.ExtensionMetaFor(extName)
	label := extLabel(extName)

	sb.WriteString(fmt.Sprintf("#### %s\n\n", label))

	if meta.Description != "" {
		sb.WriteString(meta.Description + "\n\n")
	}

	sb.WriteString("| Property | Value |\n")
	sb.WriteString("| -------- | ----- |\n")
	sb.WriteString(fmt.Sprintf("| Profile key | `%s` |\n", extName))
	if meta.OID != "" {
		sb.WriteString(fmt.Sprintf("| OID | %s |\n", meta.OID))
	}
	sb.WriteString(fmt.Sprintf("| Required | %s |\n", ext.Required))
	sb.WriteString(fmt.Sprintf("| Critical | %s |\n", ext.Critical))
	if ext.CA != nil {
		sb.WriteString(fmt.Sprintf("| CA | %s |\n", boolStr(*ext.CA)))
	}
	sb.WriteString("\n")

	sb.WriteString(criticalSentence(label, ext.Required, ext.Critical))

	if ext.CA != nil {
		if *ext.CA {
			sb.WriteString("The `cA` boolean MUST be set to TRUE; certificates issued under this profile are CA certificates.\n\n")
		} else {
			sb.WriteString("The `cA` boolean MUST be set to FALSE; certificates issued under this profile are end-entity certificates and MUST NOT be used to issue further certificates.\n\n")
		}
	}

	if len(ext.AccessDescriptions) > 0 {
		sb.WriteString("| Access Method | OID | Presence | Description |\n")
		sb.WriteString("| ------------- | --- | -------- | ----------- |\n")
		for _, ad := range ext.AccessDescriptions {
			meta := profile.AccessMethodInfo[ad.AccessMethod]
			oid := meta.OID
			if oid == "" {
				oid = ad.AccessMethod
			}
			desc := meta.Description
			if desc == "" {
				desc = "Access method identified by OID " + oid
			}
			presence := "Optional"
			if ad.Required {
				presence = "Required"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
				ad.AccessMethod, oid, presence, desc))
		}
		sb.WriteString("\n")

		var required []string
		for _, ad := range ext.AccessDescriptions {
			if ad.Required {
				required = append(required, "`"+ad.AccessMethod+"`")
			}
		}
		if len(required) > 0 {
			sb.WriteString(fmt.Sprintf(
				"An accessDescription entry MUST be present for each of the following access methods: %s.\n\n",
				strings.Join(required, ", ")))
		}
		sb.WriteString("No other access methods are permitted in this extension; " +
			"a certificate containing any access method not listed above does not conform to this profile.\n\n")
	}

	if len(ext.DistributionPoints) > 0 {
		sb.WriteString("| # | Distribution Point Name | Presence | Other Fields |\n")
		sb.WriteString("| - | ----------------------- | -------- | ------------ |\n")
		for i, dp := range ext.DistributionPoints {
			name := "-"
			switch {
			case len(dp.FullName) > 0:
				name = "`fullName` containing " + strings.Join(generalNameLabels(dp.FullName), ", ")
			case dp.NameRelativeToCRLIssuer:
				name = "`nameRelativeToCRLIssuer`"
			}
			presence := "Optional"
			if dp.Required {
				presence = "Required"
			}
			var other []string
			if dp.Reasons {
				other = append(other, "`reasons`")
			}
			if dp.CRLIssuer {
				other = append(other, "`cRLIssuer`")
			}
			otherText := "None"
			if len(other) > 0 {
				otherText = strings.Join(other, ", ")
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", i+1, name, presence, otherText))
		}
		sb.WriteString("\n")

		for i, dp := range ext.DistributionPoints {
			if !dp.Required {
				continue
			}
			sb.WriteString(fmt.Sprintf(
				"A distribution point of the form described in row %d MUST be present.\n\n", i+1))
		}

		sb.WriteString("A distribution point MUST NOT contain a name of any type other than those " +
			"listed above, and MUST NOT specify any of the optional fields shown as absent. " +
			"A certificate whose distribution points take any other form does not conform to " +
			"this profile.\n\n")
	}

	if len(ext.RequiredValues) > 0 || len(ext.OptionalValues) > 0 || len(ext.OptionalArcs) > 0 {
		valueLabel := meta.ValueLabel
		if valueLabel == "" {
			valueLabel = "Value"
		}

		// Values of the alternative name extensions are alternatives of the
		// GeneralName CHOICE, identified by a context-specific tag rather than
		// by an OID.
		if profile.SupportsGeneralNames(extName) {
			sb.WriteString(fmt.Sprintf("| %s | Tag | Presence | Description |\n", valueLabel))
			sb.WriteString("| --- | --- | -------- | ----------- |\n")
			for _, v := range ext.RequiredValues {
				sb.WriteString(generalNameRow(v, "Required"))
			}
			for _, v := range ext.OptionalValues {
				sb.WriteString(generalNameRow(v, "Optional"))
			}
			sb.WriteString("\n")

			if len(ext.RequiredValues) > 0 {
				sb.WriteString(fmt.Sprintf(
					"At least one name of each of the following types MUST be present: %s.\n\n",
					strings.Join(generalNameLabels(ext.RequiredValues), ", ")))
			}
			if len(ext.OptionalValues) > 0 {
				sb.WriteString(fmt.Sprintf(
					"Names of the following types MAY be present: %s.\n\n",
					strings.Join(generalNameLabels(ext.OptionalValues), ", ")))
			}
			sb.WriteString("No other name types are permitted in this extension; a certificate " +
				"containing a name of any type not listed above does not conform to this profile.\n\n")

			return sb.String()
		}

		// The OID column is only meaningful for values that have their own OID.
		withOID := extName == "extended_key_usage" || extName == "certificate_policies"

		if withOID {
			sb.WriteString(fmt.Sprintf("| %s | OID | Presence | Description |\n", valueLabel))
			sb.WriteString("| --- | --- | -------- | ----------- |\n")
		} else {
			sb.WriteString(fmt.Sprintf("| %s | Presence | Description |\n", valueLabel))
			sb.WriteString("| --- | -------- | ----------- |\n")
		}
		for _, v := range ext.RequiredValues {
			sb.WriteString(valueRow(extName, v, "Required", withOID))
		}
		for _, v := range ext.OptionalValues {
			sb.WriteString(valueRow(extName, v, "Optional", withOID))
		}
		for _, arc := range ext.OptionalArcs {
			sb.WriteString(arcRow(arc, withOID))
		}
		sb.WriteString("\n")

		if len(ext.RequiredValues) > 0 {
			sb.WriteString(fmt.Sprintf("Every value marked *Required* MUST be present: %s.\n\n",
				strings.Join(backtickAll(ext.RequiredValues), ", ")))
		}
		if len(ext.OptionalValues) > 0 {
			sb.WriteString(fmt.Sprintf("Values marked *Optional* MAY be present: %s.\n\n",
				strings.Join(backtickAll(ext.OptionalValues), ", ")))
		}

		if len(ext.OptionalArcs) > 0 {
			sb.WriteString(arcParagraph(ext.OptionalArcs))
		}

		if len(ext.OptionalArcs) > 0 {
			sb.WriteString("No other values are permitted in this extension; a certificate containing " +
				"any value that is neither listed above nor subordinate to one of the arcs above does not " +
				"conform to this profile.\n\n")
		} else {
			sb.WriteString("No other values are permitted in this extension; a certificate containing any value not listed above does not conform to this profile.\n\n")
		}
	}

	return sb.String()
}

// generalNameRow renders one GeneralName alternative row.
func generalNameRow(value, presence string) string {
	meta, ok := profile.GeneralNameMetaFor(value)
	if !ok {
		return fmt.Sprintf("| `%s` | - | %s | - |\n", value, presence)
	}
	return fmt.Sprintf("| %s | [%d] | %s | %s |\n",
		meta.ASN1Name, meta.Tag, presence, meta.Description)
}

// generalNameLabels renders profile keys as their ASN.1 names for use in prose.
func generalNameLabels(values []string) []string {
	labels := make([]string, 0, len(values))
	for _, v := range values {
		labels = append(labels, "`"+profile.GeneralNameLabel(v)+"`")
	}
	return labels
}

// arcRow renders one permitted-arc row for an extension value table.
func arcRow(arc string, withOID bool) string {
	prefix, ok := profile.ArcPrefix(arc)
	if !ok {
		prefix = arc
	}
	desc := fmt.Sprintf("Any identifier subordinate to the arc %s", prefix)
	if withOID {
		return fmt.Sprintf("| `%s` | %s | Optional | %s |\n", arc, prefix+".*", desc)
	}
	return fmt.Sprintf("| `%s` | Optional | %s |\n", arc, desc)
}

// arcParagraph spells out what an arc permits, so that the wildcard notation in
// the table is not the only statement of the rule.
func arcParagraph(arcs []string) string {
	var sb strings.Builder

	prefixes := make([]string, 0, len(arcs))
	for _, arc := range arcs {
		prefix, ok := profile.ArcPrefix(arc)
		if !ok {
			prefix = arc
		}
		prefixes = append(prefixes, "`"+prefix+"`")
	}

	plural := "arc"
	verb := "this arc"
	if len(arcs) > 1 {
		plural = "arcs"
		verb = "these arcs"
	}

	sb.WriteString(fmt.Sprintf(
		"In addition, any identifier subordinate to the following %s MAY be present: %s. "+
			"An identifier is subordinate to %s when it is the arc itself, or when it begins with the arc "+
			"followed by one or more further components; for example, `%s.1` and `%s.4.2` are both "+
			"subordinate to `%s`. Comparison is performed on whole arc components, so an identifier such "+
			"as `%s9` is not subordinate to `%s`.\n\n",
		plural, strings.Join(prefixes, ", "), verb,
		trimBackticks(prefixes[0]), trimBackticks(prefixes[0]), trimBackticks(prefixes[0]),
		trimBackticks(prefixes[0]), trimBackticks(prefixes[0])))

	return sb.String()
}

// trimBackticks removes the markdown backticks added for inline code.
func trimBackticks(s string) string {
	return strings.Trim(s, "`")
}

// valueRow renders one required/optional value row for an extension.
func valueRow(extName, value, presence string, withOID bool) string {
	oid, desc := "-", "-"
	switch extName {
	case "certificate_policies":
		if info, ok := profile.PolicyInfo[value]; ok {
			// Well-known policy referenced by name.
			oid, desc = info.OID, info.Description
		} else if resolved, ok := profile.PolicyOID(value); ok {
			// Referenced directly by OID.
			oid = resolved
			if name := profile.PolicyName(resolved); name != "" {
				desc = profile.PolicyInfo[name].Description
			} else {
				desc = "Certificate policy identified by OID " + resolved
			}
		}
	case "extended_key_usage":
		if info, ok := profile.ExtKeyUsageInfo[value]; ok {
			// Well-known usage referenced by name.
			oid, desc = info.OID, info.Description
		} else if resolved, ok := profile.ExtKeyUsageOID(value); ok {
			// Referenced directly by OID. Use the well-known description when
			// the OID happens to be one we know about.
			oid = resolved
			if name := profile.ExtKeyUsageName(resolved); name != "" {
				desc = profile.ExtKeyUsageInfo[name].Description
			} else {
				desc = "Application-specific key purpose identified by OID " + resolved
			}
		}
	case "key_usage":
		if d, ok := profile.KeyUsageInfo[value]; ok {
			desc = d
		}
	}
	if withOID {
		return fmt.Sprintf("| `%s` | %s | %s | %s |\n", value, oid, presence, desc)
	}
	return fmt.Sprintf("| `%s` | %s | %s |\n", value, presence, desc)
}

// backtickAll wraps each value in backticks for inline code formatting.
func backtickAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = "`" + v + "`"
	}
	return out
}

func renderProfile(p profile.Profile, raw map[string]interface{}) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Certificate Profile: %s (X.509v%d)\n\n", p.Profile.Name, p.Profile.Version))
	sb.WriteString("This profile applies only to Subscriber certificates; CA certificates are exempt from these requirements.\n\n")

	// Recognition
	if oid := p.Profile.RecognizedBy.PolicyOID; oid != "" {
		sb.WriteString(fmt.Sprintf(
			"Certificates issued under this profile can be recognized by the inclusion of a Policy OID with value %s.\n\n",
			oid))
	}

	// Validity
	sb.WriteString("### Validity\n\n")
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("| ----- | ----- |\n")
	sb.WriteString(fmt.Sprintf("| Maximum Validity (days) | %d |\n\n", p.Requirements.Validity.MaximumDays))

	// Serial number
	if sn := p.Requirements.SerialNumber; sn.Declared {
		sb.WriteString("### Serial Number\n\n")
		if sn.Required {
			sb.WriteString("The certificate serial number MUST be present.\n\n")
		}
		if sn.TextualRequirement != "" {
			// Reproduced verbatim from the profile: these requirements cannot
			// be verified by inspecting a certificate alone.
			sb.WriteString("The serial number " + sn.TextualRequirement + "\n\n")
		}
	}

	// Subject
	subject := p.Requirements.Subject
	if subject.Required || len(subject.Attributes) > 0 {
		sb.WriteString("### Subject DN Requirements\n\n")

		switch {
		case subject.Required && subject.AllowEmpty:
			sb.WriteString("The subject field MAY be empty. If it is populated, it MUST contain a non-empty RDNSequence: " +
				"at least one of the attributes listed below MUST be present, and every attribute " +
				"present MUST conform to the requirements stated for it.\n\n")
		case subject.Required:
			sb.WriteString("The subject field MUST contain a non-empty RDNSequence: " +
				"at least one of the attributes listed below MUST be present, and every attribute " +
				"present MUST conform to the requirements stated for it.\n\n")
		default:
			empty := "The subject field MAY contain an empty RDNSequence, in which case the " +
				"certificate asserts no identity through the Subject Distinguished Name"
			if _, ok := p.Requirements.Extensions["subject_alt_name"]; ok {
				empty += " and the subject is identified by the Subject Alternative Name extension instead"
			}
			sb.WriteString(empty + ". " +
				"If the RDNSequence is not empty, every attribute it contains MUST be one of the " +
				"attributes listed below and MUST conform to the requirements stated for it.\n\n")
		}
	}

	if len(subject.Attributes) > 0 {
		hasLength := false
		for _, f := range subject.Attributes {
			if f.Length.Min != nil || f.Length.Max != nil {
				hasLength = true
				break
			}
		}

		subjNames := make([]string, 0, len(subject.Attributes))
		for name := range subject.Attributes {
			subjNames = append(subjNames, name)
		}
		// Sort by the rendered X.520 name so the table reads alphabetically.
		sort.Slice(subjNames, func(i, j int) bool {
			return profile.SubjectAttributeLabel(subjNames[i]) < profile.SubjectAttributeLabel(subjNames[j])
		})

		if hasLength {
			sb.WriteString("| Attribute | Short Name | OID | Required | Min Length | Max Length |\n")
			sb.WriteString("| --------- | ---------- | --- | -------- | ---------- | ---------- |\n")
			for _, name := range subjNames {
				f := subject.Attributes[name]
				meta, _ := profile.SubjectAttributeMetaFor(name)
				minLen := "-"
				maxLen := "-"
				if f.Length.Min != nil {
					minLen = fmt.Sprintf("%d", *f.Length.Min)
				}
				if f.Length.Max != nil {
					maxLen = fmt.Sprintf("%d", *f.Length.Max)
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
					profile.SubjectAttributeLabel(name), dash(meta.ShortName), dash(meta.OID),
					boolStr(f.Required), minLen, maxLen))
			}
		} else {
			sb.WriteString("| Attribute | Short Name | OID | Required |\n")
			sb.WriteString("| --------- | ---------- | --- | -------- |\n")
			for _, name := range subjNames {
				meta, _ := profile.SubjectAttributeMetaFor(name)
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					profile.SubjectAttributeLabel(name), dash(meta.ShortName), dash(meta.OID),
					boolStr(subject.Attributes[name].Required)))
			}
		}
		sb.WriteString("\n")

		// Spell out the required attributes in prose.
		var required []string
		for _, name := range subjNames {
			if subject.Attributes[name].Required {
				required = append(required, "`"+profile.SubjectAttributeLabel(name)+"`")
			}
		}
		if len(required) > 0 {
			sb.WriteString(fmt.Sprintf("The following attributes MUST be present: %s.\n\n",
				strings.Join(required, ", ")))
		}

		sb.WriteString("No other attributes are permitted in the Subject Distinguished Name; " +
			"a certificate containing any attribute not listed above does not conform to this profile.\n\n")
	}

	// Extensions
	if len(p.Requirements.Extensions) > 0 {
		sb.WriteString("### Extensions\n\n")
		sb.WriteString("The following X.509v3 extensions are defined for this profile. " +
			"Each extension is described separately below. No other extensions are permitted; " +
			"a certificate containing any extension not listed here does not conform to this profile.\n\n")

		if p.Requirements.CoversPrecertificates() {
			sb.WriteString("This profile covers both final certificates and the Precertificates " +
				"described in RFC 6962. A Precertificate is identified by the critical Precertificate " +
				"Poison extension, which causes relying parties to reject it as a certificate. The two " +
				"forms are identical except for the Certificate Transparency extensions: a " +
				"Precertificate contains the poison extension and no Signed Certificate Timestamps, " +
				"whereas the corresponding final certificate contains the Signed Certificate Timestamps " +
				"and no poison extension. Where the table below records a requirement as applying to " +
				"one form only, that requirement is evaluated against the form of the certificate " +
				"under consideration.\n\n")
		}

		names := make([]string, 0, len(p.Requirements.Extensions))
		for name := range p.Requirements.Extensions {
			names = append(names, name)
		}
		sort.Strings(names)

		// Summary table for quick reference.
		sb.WriteString("| Extension | OID | Required | Critical |\n")
		sb.WriteString("| --------- | --- | -------- | -------- |\n")
		for _, name := range names {
			meta := profile.ExtensionMetaFor(name)
			ext := p.Requirements.Extensions[name]
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				extLabel(name), dash(meta.OID), ext.Required, ext.Critical))
		}
		sb.WriteString("\n")

		for _, name := range names {
			sb.WriteString(renderExtension(name, p.Requirements.Extensions[name]))
		}
	}

	// Rules
	if len(p.Rules) > 0 {
		sb.WriteString("### Rules\n\n")
		for _, r := range p.Rules {
			text := profile.InterpolateText(r.Text, raw)
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", r.ID, text))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s -in <template.md> -out <output.md> [-profiles dir]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s -expand <profile.yaml>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  -in file        Markdown template containing {PROFILE.<ID>} placeholders (required)\n")
	fmt.Fprintf(os.Stderr, "  -out file       Path of the generated Markdown document (required)\n")
	fmt.Fprintf(os.Stderr, "  -profiles dir   Directory containing profile YAML files (default \"profiles\")\n")
	fmt.Fprintf(os.Stderr, "  -expand file    Print the profile with everything it inherits resolved, and exit\n")
}

// expandProfile writes the profile at path with its `extends` chain resolved,
// which is the single document that the linter and the generator both see.
func expandProfile(path string, w io.Writer) error {
	loaded, err := profile.Load(path)
	if err != nil {
		return err
	}
	if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
		for _, errMsg := range validationErrs {
			fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
		}
		return fmt.Errorf("profile %s has uninterpretable requirements", path)
	}

	out, err := yaml.Marshal(loaded.Raw)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

func main() {
	templatePath := flag.String("in", "", "markdown template to process (required)")
	outputPath := flag.String("out", "", "path of the generated markdown document (required)")
	profilesDir := flag.String("profiles", "profiles", "directory containing profile YAML files")
	expandPath := flag.String("expand", "", "print the fully resolved profile at this path and exit")
	flag.Usage = usage
	flag.Parse()

	if *expandPath != "" {
		if err := expandProfile(*expandPath, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Positional fallback: profile-gen <template> <output>
	if *templatePath == "" && flag.NArg() > 0 {
		*templatePath = flag.Arg(0)
	}
	if *outputPath == "" && flag.NArg() > 1 {
		*outputPath = flag.Arg(1)
	}

	if *templatePath == "" || *outputPath == "" {
		usage()
		os.Exit(1)
	}

	templateBytes, err := os.ReadFile(*templatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading template: %v\n", err)
		os.Exit(1)
	}

	content := string(templateBytes)

	placeholderRe := regexp.MustCompile(`\{PROFILE\.([A-Z0-9_-]+)\}`)
	matches := placeholderRe.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		placeholder := m[0]
		profileID := strings.ToLower(m[1])

		yamlPath := filepath.Join(*profilesDir, profileID+".yaml")
		loaded, err := profile.Load(yamlPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load profile for %s: %v\n", placeholder, err)
			continue
		}

		// Validate that all profile requirements are interpretable
		if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
			fmt.Fprintf(os.Stderr, "Error: profile %s has uninterpretable requirements:\n", placeholder)
			for _, errMsg := range validationErrs {
				fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
			}
			os.Exit(1)
		}

		rendered := renderProfile(loaded.Profile, loaded.Raw)
		content = strings.ReplaceAll(content, placeholder, rendered)

		fmt.Printf("Injected profile '%s' for placeholder %s\n", loaded.Profile.Profile.Name, placeholder)
	}

	if err := os.WriteFile(*outputPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s\n", *outputPath)
}
