package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
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
	certPolicyOIDs   = section7.CertPolicyOIDs
	certEKUOIDs      = section7.CertEKUOIDs
	ekuDisplay       = section7.EKUDisplay
	subjectValues    = section7.SubjectValues
	isPrecertificate = section7.IsPrecertificate
	certificateKind  = section7.CertificateKind

	// lint checks a certificate against a profile.
	lint = section7.Lint
)

// ---------- lint command ----------

func lintUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s lint -in <certificate.pem> -profile <profile.yaml>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s lint -in <certificate.pem> -profiles <dir>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Lint a certificate against a profile.\n\n")
	fmt.Fprintf(os.Stderr, "  -in file        PEM-encoded X.509 certificate to lint (required)\n")
	fmt.Fprintf(os.Stderr, "  -profile file   Profile to lint against (e.g. profiles/tls-ov.yaml)\n")
	fmt.Fprintf(os.Stderr, "  -profiles dir   Directory of profiles (e.g. profiles); the one recognized by the\n")
	fmt.Fprintf(os.Stderr, "                  certificate's policy OIDs with the latest version not later\n")
	fmt.Fprintf(os.Stderr, "                  than its notBefore is used\n")
	fmt.Fprintf(os.Stderr, "\nExactly one of -profile and -profiles is required.\n")
}

// runProfile lints cert against one validated profile and prints the report.
// It returns the number of errors found.
func runProfile(cert *x509.Certificate, certPath, profilePath string, loaded *section7.Loaded) int {
	against := fmt.Sprintf("%s (%s)", loaded.Profile.Profile.Name, profilePath)
	return printReport(cert, certPath, against, lint(cert, loaded.Profile))
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

// runLint implements the lint command.
func runLint(args []string) {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	certFlag := fs.String("in", "", "PEM-encoded X.509 certificate to lint (required)")
	profilePath := fs.String("profile", "", "profile to lint against")
	profilesDir := fs.String("profiles", "", "directory of profiles to choose from")
	fs.Usage = lintUsage
	fs.Parse(args)

	if *certFlag == "" || fs.NArg() > 0 || (*profilePath == "") == (*profilesDir == "") {
		lintUsage()
		os.Exit(1)
	}
	certPath := *certFlag

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
	if *profilePath != "" {
		loaded, err := section7.Load(*profilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading profile: %v\n", err)
			os.Exit(1)
		}
		if validationErrs := loaded.Validate(); len(validationErrs) > 0 {
			fmt.Fprintf(os.Stderr, "Error: profile %s has uninterpretable requirements:\n", *profilePath)
			for _, errMsg := range validationErrs {
				fmt.Fprintf(os.Stderr, "  - %s\n", errMsg)
			}
			os.Exit(1)
		}
		if runProfile(cert, certPath, *profilePath, loaded) > 0 {
			os.Exit(2)
		}
		return
	}

	// Auto-discovery: run the one profile in the directory that applies to the certificate.
	set, err := section7.LoadProfileSet(*profilesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading profiles: %v\n", err)
		os.Exit(1)
	}

	path, loaded, finding := set.SelectProfile(cert)
	var totalErrors int
	if finding != nil {
		totalErrors = printReport(cert, certPath, "none", []Finding{*finding})
	} else {
		totalErrors = runProfile(cert, certPath, path, loaded)
	}

	if totalErrors > 0 {
		os.Exit(2)
	}
}
