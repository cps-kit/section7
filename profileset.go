package section7

import (
	"crypto/x509"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// ProfileSet is a directory of profiles, loaded and validated once, from which
// the one profile that applies to each certificate is chosen. It is not
// modified after loading, so it may be used from many goroutines at once.
type ProfileSet struct {
	paths    []string
	profiles map[string]*Loaded
}

// LoadProfileSet loads every profile in dir and validates it. A profile that
// cannot be interpreted makes the whole set an error, so that no certificate
// is ever linted against one.
func LoadProfileSet(dir string) (*ProfileSet, error) {
	profiles, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(profiles))
	for path := range profiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var problems []string
	for _, path := range paths {
		for _, msg := range profiles[path].Validate() {
			problems = append(problems, path+": "+msg)
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("profiles in %s have uninterpretable requirements:\n  - %s",
			dir, strings.Join(problems, "\n  - "))
	}

	return &ProfileSet{paths: paths, profiles: profiles}, nil
}

// SelectProfile returns the profile recognized by the certificate's policy
// OIDs whose version is the latest not later than its notBefore. A profile
// without a version is not held to its notBefore, but loses to any profile
// with one. When no single profile qualifies, it returns the finding that
// explains why.
func (s *ProfileSet) SelectProfile(cert *x509.Certificate) (string, *Loaded, *Finding) {
	oids := CertPolicyOIDs(cert)

	var tooNew, latest []string
	var latestVersion time.Time
	for _, path := range s.paths {
		p := s.profiles[path].Profile
		if want := p.Profile.RecognizedBy.PolicyOID; want == "" || !slices.Contains(oids, want) {
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
		return latest[0], s.profiles[latest[0]], nil
	case len(latest) > 1:
		shared := "no version"
		if !latestVersion.IsZero() {
			shared = "version " + latestVersion.Format(time.RFC3339Nano)
		}
		return "", nil, &Finding{
			RuleID:   "PROFILE-003",
			Severity: Error,
			Message: fmt.Sprintf(
				"more than one profile recognized by the certificate's policy OIDs has the latest "+
					"version not later than its notBefore %s, so none can be chosen (found: %s, all with %s)",
				cert.NotBefore.Format(time.RFC3339), strings.Join(latest, ", "), shared),
		}
	case len(tooNew) > 0:
		return "", nil, &Finding{
			RuleID:   "PROFILE-002",
			Severity: Error,
			Message: fmt.Sprintf(
				"no profile recognized by the certificate's policy OIDs has a version not later than its notBefore %s (found: %s)",
				cert.NotBefore.Format(time.RFC3339), strings.Join(tooNew, ", ")),
		}
	default:
		found := "none"
		if len(oids) > 0 {
			found = strings.Join(oids, ", ")
		}
		return "", nil, &Finding{
			RuleID:   "PROFILE-001",
			Severity: Error,
			Message: fmt.Sprintf(
				"no profile is recognized by the certificate's policy OIDs (found: %s)", found),
		}
	}
}

// LintCertificate chooses the profile for cert and lints the certificate
// against it. The path is empty when no profile could be chosen, and the
// findings say why.
func (s *ProfileSet) LintCertificate(cert *x509.Certificate) (string, []Finding) {
	path, loaded, f := s.SelectProfile(cert)
	if f != nil {
		return "", []Finding{*f}
	}
	return path, Lint(cert, loaded.Profile)
}
