This repository contains a CPS Section 7 certificate profile generator and linter.

The profiles located in /profiles, are codified certificate profiles, against which the generator and linter will work.

The generator can inject the profiles into a CPS document.
The linter can validate certificates against the profiles.

## Profiles

A profile describes every field and extension a conforming certificate may contain. The lists are exhaustive: anything a profile does not describe is reported as a violation, so a profile that says nothing about extensions permits none. Permitting something is always an explicit act.

The fields a profile can describe follow the TBSCertificate of RFC 5280: the certificate version, the serial number, the signature algorithm, the issuer distinguished name, the validity period, the subject distinguished name, the subject public key algorithm with its key sizes or curves, and the extensions. The two remaining fields, `issuerUniqueID` and `subjectUniqueID`, are never permitted (see [Unique identifiers](#unique-identifiers)). The generated document, the lint report and `profile-gen -expand` all present them in that order. The optional `profile.version` is an RFC 3339 timestamp, such as `2026-10-29T12:00:00Z`, recording the revision of the profile document itself; when present, the generated document shows it in the profile's heading.

Files whose name begins with `_` are shared definitions rather than profiles of their own, and are skipped by profile discovery. A profile pulls them in with `extends`, naming one file or several:

```yaml
extends:
  - _tls.yaml
  - _subject-organization.yaml
```

Bases are merged in the order listed and the profile is merged last, so a profile always wins over what it inherits. Mappings merge key by key, so a profile can add an extension or an attribute without restating the rest. Sequences are replaced, so a profile that narrows an inherited list states that list in full.

To review a profile as a single document, with everything it inherits resolved:

```
profile-gen -expand profiles/tls-ov.yaml
```

## Supported YAML configuration

Profiles are structured as a YAML document with a top-level `profile` block and a `requirements` block. The linter understands the following configuration patterns, described here in the order the fields appear in a certificate.

### Version

```yaml
requirements:
  version: v3
```

`requirements.version` is required and must be `v1`, `v2` or `v3`.

### Serial number

```yaml
requirements:
  serial_number:
    minimum_bit_length: 1
    maximum_bit_length: 159
```

The linter always applies RFC 5280: the serial number must be greater than zero and its DER encoding must not exceed 20 octets. The optional block adds:

- `requirements.serial_number.minimum_bit_length` (default 1)
- `requirements.serial_number.maximum_bit_length` (default 159, which is also the most it can be: a positive INTEGER needs a leading zero bit, so 20 octets hold at most 159 bits)
- `requirements.serial_number.textual_requirement`

CSPRNG output can begin with zero bits, so a serial number carrying 64 bits of it can be shorter than 64 bits, and rejecting such values would itself reduce the entropy. State entropy requirements in `textual_requirement` rather than as a `minimum_bit_length`.

### Signature algorithm

```yaml
requirements:
  signature_algorithm:
    allowed:
      - sha256WithRSAEncryption
      - ecdsa-with-SHA256
```

The list is exhaustive, and a profile that lists none permits none. Entries may be a well-known name (`sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`, `id-RSASSA-PSS`, `ecdsa-with-SHA256`, `ecdsa-with-SHA384`, `ecdsa-with-SHA512`, `id-Ed25519`, `id-Ed448`) or a raw OID.

### Issuer DN requirements

The `requirements.issuer` block has the same form as the subject block below, and its attribute list is equally exhaustive. The issuer is never permitted to be empty.

```yaml
requirements:
  issuer:
    attributes:
      country_name:
        required: true
      organization_name:
        required: true
      common_name:
        required: true
```

### Validity

```yaml
requirements:
  validity:
    maximum_days: 398
```

`requirements.validity.maximum_days` is required.

### Subject DN requirements

The `requirements.subject` block lists the attributes permitted in the subject DN and which of them are required. The list is exhaustive. If no attribute is required, the subject may be an empty RDNSequence, in which case RFC 5280 requires a critical Subject Alternative Name extension.

```yaml
requirements:
  subject:
    attributes:
      country_name:
        required: true
      locality_name:
        required: false
        length:
          min: 2
          max: 64
      organization_name:
        required: true
      common_name:
        required: true
```

Supported subject attribute names include:

- `common_name`
- `surname`
- `serial_number`
- `country_name`
- `locality_name`
- `state_or_province_name`
- `street_address`
- `organization_name`
- `organizational_unit_name`
- `title`
- `given_name`
- `initials`
- `pseudonym`
- `generation_qualifier`
- `business_category`
- `postal_code`
- `organization_identifier`
- `domain_component`
- `user_id`
- `email_address`
- `jurisdiction_locality_name`
- `jurisdiction_state_or_province_name`
- `jurisdiction_country_name`

Common aliases are accepted as well, such as `country`, `locality`, `state`, `province`, `organizational_unit`, `email`, and `dns`/`ip` for name-type contexts where relevant.

Each attribute can specify:

- `required: true|false`
- `length.min`
- `length.max`

### Subject public key

```yaml
requirements:
  public_key:
    algorithms:
      - name: rsaEncryption
        key_sizes:
          - 2048
          - 4096
      - name: id-ecPublicKey
        curves:
          - P-256
```

The list is exhaustive, and a profile that lists none permits none. `name` may be a well-known name (`rsaEncryption`, `id-RSASSA-PSS`, `id-ecPublicKey`, `id-Ed25519`, `id-Ed448`) or a raw OID. `key_sizes` applies to RSA keys and `curves` to elliptic curve keys; both are required for those algorithms and are exhaustive in the same way. Curves may be written as `P-256`, `secp256r1`, `prime256v1` or `nistp256`, and likewise for P-384 and P-521.

### Unique identifiers

The optional `issuerUniqueID` and `subjectUniqueID` fields of the TBSCertificate are forbidden by the Baseline Requirements. There is no profile setting for them: the linter reports `UNIQUEID-001` for any certificate that contains either field, whatever profile it is linted against, and the generated document states that both MUST NOT be present.

### Extension requirements

The `requirements.extensions` map describes every extension a conforming certificate may contain. The list is exhaustive: unlisted extensions are rejected.

```yaml
requirements:
  extensions:
    basic_constraints:
      required: true
      critical: true
      ca: false

    key_usage:
      required: true
      critical: true
      required_values:
        - digitalSignature
        - keyEncipherment

    subject_alt_name:
      required: true
      critical: false
      required_values:
        - dns_name
      optional_values:
        - ip_address

    authority_information_access:
      required: true
      critical: false
      access_descriptions:
        - access_method: id-ad-ocsp
          required: true
        - access_method: id-ad-caIssuers
          required: true
```

Supported extension keys include:

- `basic_constraints`
- `key_usage`
- `extended_key_usage`
- `subject_alt_name`
- `issuer_alt_name`
- `authority_key_identifier`
- `subject_key_identifier`
- `certificate_policies`
- `policy_mappings`
- `policy_constraints`
- `name_constraints`
- `inhibit_any_policy`
- `crl_distribution_points`
- `freshest_crl`
- `subject_directory_attributes`
- `authority_information_access`
- `subject_information_access`
- `qc_statements`
- `tls_feature`
- `ocsp_nocheck`
- `signed_certificate_timestamps`
- `precertificate_poison`
- `cabf_organization_identifier`

Custom extensions may also be declared by raw OID using `extension_oid`.

Each extension entry may contain:

- `required: true|false|final_only|precertificate_only`
- `critical: true|false|optional`
- `ca: true|false` (for `basic_constraints` only)
- `required_values: []`
- `optional_values: []`
- `optional_arcs: []` (for OID-valued extensions)
- `access_descriptions: []`
- `distribution_points: []`

### Notes

- Profiles are merged through `extends`, with the last file in the list winning on conflicts.
- Mappings are merged recursively; sequences replace inherited values.
- The profile schema is strict: unsupported keys are rejected during validation.

## Generating the CPS document

The generator reads one or more profile YAML files and expands inherited fragments before rendering a CPS document.

Typical workflow:

1. Write or update a profile under `profiles/`.
2. Optionally inherit shared fragments with `extends`.
3. Run the generator against the profile you want to materialize.

Example:

```bash
profile-gen -expand profiles/tls-ov.yaml
```

This expands inherited fragments and prints the fully resolved profile as YAML.

To generate a CPS document, give a Markdown template whose `{PROFILE.<ID>}` placeholders name profiles in a directory; `{PROFILE.TLS-OV}` is replaced with the rendering of `tls-ov.yaml`:

```bash
profile-gen -in template.md -out cps.md -profiles profiles
```

The generator will emit the CPS content using the profile metadata and requirements. If you want a single merged view for debugging or documentation, use the `-expand` flag as shown above.

For a full command reference:

```bash
profile-gen -h
```

The generator and linter both operate on the same profile model, so a profile that validates with `profile-lint` should also be suitable for CPS generation.

## Linting a certificate

The linter reads profiles only from the file or directory it is given; none are built in.

```bash
profile-lint cert.pem profiles/tls-ov.yaml
profile-lint cert.pem profiles
```

Given a file, it lints against that profile. Given a directory, it uses the one profile recognized by the certificate's policy OIDs whose `profile.version` is the latest not later than the certificate's notBefore, and otherwise reports why none could be chosen.

## Mascot

Meet Sherlock.

![Sherlock](server/images/mascot.png)
