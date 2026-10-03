This repository contains a CPS Section 7 certificate profile generator and linter.

The profiles located in /profiles, are codified certificate profiles, against which the generator and linter will work.

The generator can inject the profiles into a CPS document.
The linter can validate certificates against the profiles.

## Profiles

A profile describes every field and extension a conforming certificate may contain. The lists are exhaustive: anything a profile does not describe is reported as a violation, so a profile that says nothing about extensions permits none. Permitting something is always an explicit act.

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

Profiles are structured as a YAML document with a top-level `profile` block and a `requirements` block. The linter understands the following configuration patterns.

### Subject DN requirements

The `requirements.subject` block can describe the subject DN as a whole and the individual attributes that are permitted or required.

```yaml
requirements:
  subject:
    required: true
    allow_empty: true
    attributes:
      common_name:
        required: true
      organization_name:
        required: true
      country_name:
        required: true
      locality_name:
        required: false
        length:
          min: 2
          max: 64
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

### Serial number and validity

```yaml
requirements:
  validity:
    maximum_days: 398

  serial_number:
    required: true
    minimum_octets: 8
    maximum_bit_length: 159
```

The linter also supports:

- `requirements.validity.maximum_days`
- `requirements.serial_number.required`
- `requirements.serial_number.maximum_bit_length`
- `requirements.serial_number.minimum_octets`
- `requirements.serial_number.textual_requirement`

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

To generate a CPS document from a profile:

```bash
profile-gen profiles/tls-ov.yaml
```

The generator will emit the CPS content using the profile metadata and requirements. If you want a single merged view for debugging or documentation, use the `-expand` flag as shown above.

For a full command reference:

```bash
profile-gen -h
```

The generator and linter both operate on the same profile model, so a profile that validates with `profile-lint` should also be suitable for CPS generation.
