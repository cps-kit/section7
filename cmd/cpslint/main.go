// Command cpslint lints a single X.509 certificate against a CP/CPS profile.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	lintpkg "cpsgen/internal/lint"
	"cpsgen/internal/profile"
)

// Local aliases onto the shared lint engine, so that this command (and its
// tests) can keep using short, unqualified names.
type (
	Severity = lintpkg.Severity
	Finding  = lintpkg.Finding
)

const (
	Error   = lintpkg.Error
	Warning = lintpkg.Warning
	Info    = lintpkg.Info
)

var (
	certPolicyOIDs     = lintpkg.CertPolicyOIDs
	certMatchesProfile = lintpkg.CertMatchesProfile
	certEKUOIDs        = lintpkg.CertEKUOIDs
	ekuDisplay         = lintpkg.EKUDisplay
	subjectValues      = lintpkg.SubjectValues
	isPrecertificate   = lintpkg.IsPrecertificate
	certificateKind    = lintpkg.CertificateKind

	// lint checks a certificate against a profile.
	lint = lintpkg.Lint
)

// ---------- Main ----------

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: cpslint <certificate.pem> [profile.yaml]\n\n")
	fmt.Fprintf(os.Stderr, "  certificate.pem  PEM-encoded X.509 certificate to lint\n")
	fmt.Fprintf(os.Stderr, "  profile.yaml     Profile YAML file (e.g. profiles/tls-ov.yaml).\n")
	fmt.Fprintf(os.Stderr, "                   When omitted, every profile in ./profiles is\n")
	fmt.Fprintf(os.Stderr, "                   matched against the certificate's policy OIDs.\n")
}

// runProfile lints cert against one loaded profile and prints the report.
// It returns the number of errors found.
func runProfile(cert *x509.Certificate, certPath, profilePath string, loaded *profile.Loaded) int {
	// Validate that all profile requirements are interpretable
	if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
		fmt.Fprintf(os.Stderr, "Error: profile %s has uninterpretable requirements:\n", profilePath)
		for _, errMsg := range validationErrs {
			fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
		}
		os.Exit(1)
	}

	fmt.Printf("Linting certificate:  %s\n", certPath)
	fmt.Printf("Against profile:      %s (%s)\n", loaded.Profile.Profile.Name, profilePath)
	fmt.Printf("Kind:                 %s\n", certificateKind(cert))
	fmt.Printf("Subject:              %s\n", cert.Subject.String())
	fmt.Printf("Validity:             %s → %s\n",
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	if oids := certPolicyOIDs(cert); len(oids) > 0 {
		fmt.Printf("Policy OIDs:          %s\n", strings.Join(oids, ", "))
	}
	fmt.Println(strings.Repeat("─", 72))

	findings := lint(cert, loaded.Profile)
	for _, f := range findings {
		fmt.Println(f)
	}
	errors, warnings, infos := lintpkg.Counts(findings)

	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("Result: %d error(s), %d warning(s), %d info finding(s)\n", errors, warnings, infos)

	return errors
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		usage()
		os.Exit(1)
	}

	certPath := os.Args[1]

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

	// Explicit profile
	if len(os.Args) == 3 {
		profilePath := os.Args[2]
		loaded, err := profile.Load(profilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading profile: %v\n", err)
			os.Exit(1)
		}
		if runProfile(cert, certPath, profilePath, loaded) > 0 {
			os.Exit(2)
		}
		return
	}

	// Auto-discovery: run every profile whose recognized_by.policy_oid is
	// present in the certificate.
	profiles, err := profile.LoadDir("profiles")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
		os.Exit(1)
	}

	paths := make([]string, 0, len(profiles))
	for path := range profiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	totalErrors, matched := 0, 0
	for _, path := range paths {
		loaded := profiles[path]
		if !certMatchesProfile(cert, loaded.Profile) {
			continue
		}
		if matched > 0 {
			fmt.Println()
		}
		matched++
		totalErrors += runProfile(cert, certPath, path, loaded)
	}

	if matched == 0 {
		fmt.Fprintf(os.Stderr,
			"Error: no profile matched the certificate's policy OIDs (%s)\n",
			strings.Join(certPolicyOIDs(cert), ", "))
		os.Exit(1)
	}

	if totalErrors > 0 {
		os.Exit(2)
	}
}
