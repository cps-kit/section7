package section7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// certWithPolicies returns a parsed certificate carrying the given policy OIDs.
func certWithPolicies(t *testing.T, oids ...string) *x509.Certificate {
	t.Helper()

	var policies []x509.OID
	for _, s := range oids {
		oid, err := x509.ParseOID(s)
		if err != nil {
			t.Fatalf("bad OID %q: %v", s, err)
		}
		policies = append(policies, oid)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true,
		Policies:              policies,
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

// setOf builds a ProfileSet directly, without loading or validating.
func setOf(profiles map[string]*Loaded) *ProfileSet {
	paths := make([]string, 0, len(profiles))
	for path := range profiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return &ProfileSet{paths: paths, profiles: profiles}
}

// TestSelectLatestVersion verifies that the one profile selected is the one
// whose version is the latest not later than the certificate's notBefore.
func TestSelectLatestVersion(t *testing.T) {
	cert := certWithPolicies(t, "2.23.140.1.2.2", "2.23.140.1.2.3")
	profile := func(oid string, version time.Time) *Loaded {
		return &Loaded{Profile: Profile{Profile: Meta{
			RecognizedBy: RecognizedBy{PolicyOID: oid},
			Version:      ProfileVersion{Time: version},
		}}}
	}
	older := cert.NotBefore.Add(-2 * time.Hour)
	past := cert.NotBefore.Add(-time.Hour)
	future := cert.NotBefore.Add(time.Hour)

	tests := []struct {
		name     string
		profiles map[string]*Loaded
		selected string
		ruleID   string
	}{
		{"latest of the older versions", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", older),
			"b.yaml": profile("2.23.140.1.2.2", past),
			"c.yaml": profile("2.23.140.1.2.2", future),
		}, "b.yaml", ""},
		{"across policy OIDs", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", past),
			"b.yaml": profile("2.23.140.1.2.3", older),
		}, "a.yaml", ""},
		{"unrecognized profile ignored", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", older),
			"b.yaml": profile("2.23.140.1.2.1", past),
		}, "a.yaml", ""},
		{"no version", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", time.Time{}),
		}, "a.yaml", ""},
		{"a version beats no version", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", time.Time{}),
			"b.yaml": profile("2.23.140.1.2.2", older),
		}, "b.yaml", ""},
		{"version equals notBefore", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", past),
			"b.yaml": profile("2.23.140.1.2.2", cert.NotBefore),
		}, "b.yaml", ""},
		{"tied latest versions", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", past),
			"b.yaml": profile("2.23.140.1.2.3", past),
			"c.yaml": profile("2.23.140.1.2.2", older),
		}, "", "PROFILE-003"},
		{"tied without versions", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", time.Time{}),
			"b.yaml": profile("2.23.140.1.2.3", time.Time{}),
		}, "", "PROFILE-003"},
		{"only newer versions", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.2", future),
		}, "", "PROFILE-002"},
		{"no policy match", map[string]*Loaded{
			"a.yaml": profile("2.23.140.1.2.1", past),
		}, "", "PROFILE-001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := setOf(tt.profiles)
			selected, loaded, f := set.SelectProfile(cert)
			if selected != tt.selected {
				t.Errorf("selected %q, want %q", selected, tt.selected)
			}
			if selected != "" && loaded != tt.profiles[selected] {
				t.Errorf("selected %q but returned a different profile", selected)
			}
			switch {
			case tt.ruleID == "" && f != nil:
				t.Errorf("unexpected finding %v", f)
			case tt.ruleID != "" && (f == nil || f.RuleID != tt.ruleID || f.Severity != Error):
				t.Errorf("got finding %v, want a %s error", f, tt.ruleID)
			}
		})
	}
}

// TestSelectUnmatchedListsFound verifies the PROFILE-001 error names the
// policy OIDs the certificate carries, or says it carries none.
func TestSelectUnmatchedListsFound(t *testing.T) {
	set := setOf(map[string]*Loaded{
		"a.yaml": {Profile: Profile{Profile: Meta{RecognizedBy: RecognizedBy{PolicyOID: "2.23.140.1.2.2"}}}},
	})
	tests := []struct {
		name  string
		cert  *x509.Certificate
		found string
	}{
		{"other policies", certWithPolicies(t, "1.2.3.4", "1.2.3.5"), "(found: 1.2.3.4, 1.2.3.5)"},
		{"no policies", certWithPolicies(t), "(found: none)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, findings := set.LintCertificate(tt.cert)
			if path != "" || len(findings) != 1 {
				t.Fatalf("got %q and %v, want one finding and no profile", path, findings)
			}
			if f := findings[0]; f.RuleID != "PROFILE-001" || f.Severity != Error || !strings.HasSuffix(f.Message, tt.found) {
				t.Errorf("got %v, want a PROFILE-001 error ending %q", f, tt.found)
			}
		})
	}
}

// TestLoadProfileSetShippedProfiles verifies the shipped profiles load as a set
// and that an OV certificate is linted against the OV profile.
func TestLoadProfileSetShippedProfiles(t *testing.T) {
	set, err := LoadProfileSet("profiles")
	if err != nil {
		t.Fatalf("loading profiles: %v", err)
	}

	path, findings := set.LintCertificate(certWithPolicies(t, "2.23.140.1.2.2"))
	if want := filepath.Join("profiles", "tls-ov.yaml"); path != want {
		t.Fatalf("linted against %q, want %q", path, want)
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "POLICY-001" && f.Severity == Info {
			found = true
		}
	}
	if !found {
		t.Errorf("the OV profile should recognize the certificate, got: %v", findings)
	}
}

// TestLoadProfileSetRejectsInvalidProfile verifies that one profile the tools
// cannot interpret makes the whole set an error.
func TestLoadProfileSetRejectsInvalidProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("profile:\n  name: Bad\n"), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	_, err := LoadProfileSet(dir)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "bad.yaml")+": requirements.version is missing") {
		t.Errorf("an invalid profile should be reported by path, got: %v", err)
	}
}

// TestLoadDirKeepsSharedBasesApart verifies that a base parsed once for several
// profiles is not changed for one by what another adds to it.
func TestLoadDirKeepsSharedBasesApart(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"_base.yaml": "requirements:\n  subject:\n    attributes:\n      country_name: {}\n",
		"a.yaml":     "extends: _base.yaml\nrequirements:\n  subject:\n    attributes:\n      common_name: {}\n",
		"b.yaml":     "extends: _base.yaml\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	profiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("loading profiles: %v", err)
	}
	a := profiles[filepath.Join(dir, "a.yaml")].Profile.Requirements.Subject.Attributes
	b := profiles[filepath.Join(dir, "b.yaml")].Profile.Requirements.Subject.Attributes
	if len(a) != 2 {
		t.Errorf("a.yaml should have its own and the inherited attribute, got %v", a)
	}
	if len(b) != 1 {
		t.Errorf("b.yaml should have only the inherited attribute, got %v", b)
	}
}

// TestProfileSetConcurrentUse verifies a set gives the same result when used
// from many goroutines, while extensions are being registered. Run with -race.
func TestProfileSetConcurrentUse(t *testing.T) {
	set, err := LoadProfileSet("profiles")
	if err != nil {
		t.Fatalf("loading profiles: %v", err)
	}
	cert := certWithPolicies(t, "2.23.140.1.2.2")
	wantPath, want := set.LintCertificate(cert)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := RegisterExtension(fmt.Sprintf("concurrency_test_%d", i), fmt.Sprintf("1.3.6.1.4.1.99999.%d", i)); err != nil {
				t.Errorf("registering extension: %v", err)
			}
		}
	}()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				path, got := set.LintCertificate(cert)
				if path != wantPath || !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent lint gave %q %v, want %q %v", path, got, wantPath, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}
