package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandFollowsCertificateOrder checks expand prints the requirements in
// TBSCertificate order and the attributes in encoding order, rather than in
// the alphabetical order the YAML encoder would choose.
func TestExpandFollowsCertificateOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	doc := `
requirements:
  subject:
    attributes:
      common_name:
        required: true
      country_name:
        required: true
  validity:
    maximum_days: 398
  serial_number:
    maximum_bit_length: 159
  version: v3
  public_key:
    algorithms: [{name: rsaEncryption, key_sizes: [2048]}]
  signature_algorithm:
    allowed: [sha256WithRSAEncryption]
  issuer:
    attributes: {common_name: {}}
profile:
  name: Order Test
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing profile: %v", err)
	}

	var buf bytes.Buffer
	if err := expandProfile(path, &buf); err != nil {
		t.Fatalf("expanding profile: %v", err)
	}
	out := buf.String()

	pos := 0
	for _, item := range []string{
		"profile:", "requirements:", "version: v3", "serial_number:",
		"validity:", "subject:", "country_name:", "common_name:",
	} {
		i := strings.Index(out[pos:], item)
		if i == -1 {
			t.Fatalf("%q should appear after the preceding item, got:\n%s", item, out)
		}
		pos += i + len(item)
	}
}
