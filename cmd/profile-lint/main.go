// Lint a single X.509 certificate against a CP/CPS profile.
//
// Negative serial numbers are parsed so that they are reported, not refused.
//
//go:debug x509negativeserial=1
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cps-kit/section7"
)

// Local aliases onto the shared lint engine, so that this command (and its
// tests) can keep using short, unqualified names.
type (
	Severity = section7.Severity
	Finding  = section7.Finding
)

const (
	Error   = section7.Error
	Warning = section7.Warning
	Info    = section7.Info
)

var (
	certPolicyOIDs     = section7.CertPolicyOIDs
	certMatchesProfile = section7.CertMatchesProfile
	certEKUOIDs        = section7.CertEKUOIDs
	ekuDisplay         = section7.EKUDisplay
	subjectValues      = section7.SubjectValues
	isPrecertificate   = section7.IsPrecertificate
	certificateKind    = section7.CertificateKind

	// lint checks a certificate against a profile.
	lint = section7.Lint
)

// ---------- Main ----------

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <certificate.pem> <profile.yaml | profile-directory>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  certificate.pem    PEM-encoded X.509 certificate to lint\n")
	fmt.Fprintf(os.Stderr, "  profile.yaml       Profile to lint against (e.g. profiles/tls-ov.yaml)\n")
	fmt.Fprintf(os.Stderr, "  profile-directory  Directory of profiles (e.g. profiles). The one that is\n")
	fmt.Fprintf(os.Stderr, "                     recognized by the certificate's policy OIDs and has\n")
	fmt.Fprintf(os.Stderr, "                     the latest version not later than its notBefore is used.\n")
}

// runProfile lints cert against one loaded profile and prints the report.
// It returns the number of errors found.
func runProfile(cert *x509.Certificate, certPath, profilePath string, loaded *section7.Loaded) int {
	// Validate that all profile requirements are interpretable
	if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
		fmt.Fprintf(os.Stderr, "Error: profile %s has uninterpretable requirements:\n", profilePath)
		for _, errMsg := range validationErrs {
			fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
		}
		os.Exit(1)
	}

	against := fmt.Sprintf("%s (%s)", loaded.Profile.Profile.Name, profilePath)
	return printReport(cert, certPath, against, lint(cert, loaded.Profile))
}

// unmatchedFinding reports that no profile is recognized by the certificate's
// policy OIDs.
func unmatchedFinding(cert *x509.Certificate) Finding {
	found := "none"
	if oids := certPolicyOIDs(cert); len(oids) > 0 {
		found = strings.Join(oids, ", ")
	}
	return Finding{
		RuleID:   "PROFILE-001",
		Severity: Error,
		Message: fmt.Sprintf(
			"no profile is recognized by the certificate's policy OIDs (found: %s)", found),
	}
}

// selectProfile returns the profile recognized by the certificate's policy OIDs
// whose version is the latest not later than its notBefore. A profile without
// a version is not held to its notBefore, but loses to any profile with one.
// When no single profile qualifies, it returns the finding that explains why.
func selectProfile(cert *x509.Certificate, profiles map[string]*section7.Loaded) (string, *Finding) {
	paths := make([]string, 0, len(profiles))
	for path := range profiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var tooNew, latest []string
	var latestVersion time.Time
	for _, path := range paths {
		p := profiles[path].Profile
		if !certMatchesProfile(cert, p) {
			continue
		}
		version := p.Profile.Version.Time
		switch {
		case version.After(cert.NotBefore):
			tooNew = append(tooNew, fmt.Sprintf("%s version %s", path, version.Format(time.RFC3339Nano)))
		case len(latest) == 0 || version.After(latestVersion):
			latest, latestVersion = []string{path}, version
		case version.Equal(latestVersion):
			latest = append(latest, path)
		}
	}

	switch {
	case len(latest) == 1:
		return latest[0], nil
	case len(latest) > 1:
		shared := "no version"
		if !latestVersion.IsZero() {
			shared = "version " + latestVersion.Format(time.RFC3339Nano)
		}
		return "", &Finding{
			RuleID:   "PROFILE-003",
			Severity: Error,
			Message: fmt.Sprintf(
				"more than one profile recognized by the certificate's policy OIDs has the latest "+
					"version not later than its notBefore %s, so none can be chosen (found: %s, all with %s)",
				cert.NotBefore.Format(time.RFC3339), strings.Join(latest, ", "), shared),
		}
	case len(tooNew) > 0:
		return "", &Finding{
			RuleID:   "PROFILE-002",
			Severity: Error,
			Message: fmt.Sprintf(
				"no profile recognized by the certificate's policy OIDs has a version not later than its notBefore %s (found: %s)",
				cert.NotBefore.Format(time.RFC3339), strings.Join(tooNew, ", ")),
		}
	default:
		f := unmatchedFinding(cert)
		return "", &f
	}
}

// printReport prints the findings for cert and returns the number of errors.
func printReport(cert *x509.Certificate, certPath, against string, findings []Finding) int {
	fmt.Printf("Linting certificate:  %s\n", certPath)
	fmt.Printf("Against profile:      %s\n", against)
	fmt.Printf("Kind:                 %s\n", certificateKind(cert))
	fmt.Printf("Subject:              %s\n", cert.Subject.String())
	fmt.Printf("Validity:             %s → %s\n",
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	if oids := certPolicyOIDs(cert); len(oids) > 0 {
		fmt.Printf("Policy OIDs:          %s\n", strings.Join(oids, ", "))
	}
	fmt.Println(strings.Repeat("─", 72))

	for _, f := range findings {
		fmt.Println(f)
	}
	errors, warnings, infos := section7.Counts(findings)

	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("Result: %d error(s), %d warning(s), %d info finding(s)\n", errors, warnings, infos)

	return errors
}

func main() {
	if len(os.Args) != 3 {
		usage()
		os.Exit(1)
	}

	certPath, profileSource := os.Args[1], os.Args[2]

	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: no PEM block found in %s\n", certPath)
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(profileSource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Explicit profile
	if !info.IsDir() {
		loaded, err := section7.Load(profileSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading profile: %v\n", err)
			os.Exit(1)
		}
		if runProfile(cert, certPath, profileSource, loaded) > 0 {
			os.Exit(2)
		}
		return
	}

	// Auto-discovery: run the one profile in the directory that applies to the certificate.
	profiles, err := section7.LoadDir(profileSource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
		os.Exit(1)
	}

	path, finding := selectProfile(cert, profiles)
	var totalErrors int
	if finding != nil {
		totalErrors = printReport(cert, certPath, "none", []Finding{*finding})
	} else {
		totalErrors = runProfile(cert, certPath, path, profiles[path])
	}

	if totalErrors > 0 {
		os.Exit(2)
	}
}
