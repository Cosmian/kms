# Covercrypt Policy Management

Extract or view policies of existing keys, and create a binary policy from specifications.

```sh
ckms cc policy <COMMAND>
```

## create

Create a policy binary file from policy specifications.

```sh
ckms cc policy create [OPTIONS] -s <SPECIFICATIONS_FILE> -p <OUTPUT_FILE>
```

The policy specifications must be passed as a JSON in a file, for example:

```json
{
        "Security Level::<": [
                "Protected",
                "Confidential",
                "Top Secret::+"
        ],
        "Department": [
                "R&D",
                "HR",
                "MKG",
                "FIN"
        ]
}
```

These specifications create a policy where:

- the policy is defined with 2 policy axes: `Security Level` and `Department`
- the `Security Level` axis is hierarchical as indicated by the `::<` suffix,
- the `Security Level` axis has 3 possible values: `Protected`, `Confidential`, and `Top Secret`,
- the `Department` axis has 4 possible values: `R&D`, `HR`, `MKG`, and `FIN`,
- all partitions which are `Top Secret` will be encrypted using post-quantum hybridized cryptography, as indicated by the `::+` suffix on the value,
- all other partitions will use classic cryptography.

**Usage:**

```sh
 ckms cc policy create [OPTIONS]
```

**Options:**

```sh
  -s, --specifications <POLICY_SPECIFICATIONS_FILE>
          The policy specifications filename.
          The policy is expressed as a JSON object describing the Policy axes.
          See the documentation for details

          [default: policy_specifications.json]

  -p, --policy <POLICY_BINARY_FILE>
          The output binary policy file generated from the specifications file

          [default: policy.bin]

  -h, --help
          Print help (see a summary with '-h')
```

## view

View the policy of an existing public or private master key.

```sh
ckms cc policy view [OPTIONS]
```

- Use the `--key-id` switch to extract the policy from a key stored in the KMS.
- Use the `--key-file` switch to extract rhe policy from a Key exported as TTLV.

**Usage:**

```sh
 ckms cc policy view [OPTIONS]
```

**Options:**

```sh
  -i, --key-id <KEY_ID>
          The public or private master key ID if the key is stored in the KMS

  -f, --key-file <KEY_FILE>
          If `key-id` is not provided, the file containing the public or private master key in TTLV format

  -d, --detailed
          Show all the policy details rather than just the specifications

  -h, --help
          Print help (see a summary with '-h')
```

## specs

Extract the policy specifications from a public or private master key to a policy specifications file.

```sh
ckms cc policy specs [OPTIONS]
```

- Use the `--key-id` switch to extract the policy from a key stored in the KMS.
- Use the `--key-file` switch to extract the policy from a Key exported as TTLV.

**Usage:**

```sh
 ckms cc policy specs [OPTIONS]
```

**Options:**

```sh
  -i, --key-id <KEY_ID>
          The public or private master key ID if the key is stored in the KMS

  -f, --key-file <KEY_FILE>
          If `key-id` is not provided, the file containing the public or private master key in JSON TTLV format

  -s, --specifications <POLICY_SPECS_FILE>
          The output policy specifications file

          [default: policy_specifications.json]

  -h, --help
          Print help (see a summary with '-h')
```

## binary

Extract the policy from a public or private master key to a policy binary file.

```sh
ckms cc policy binary [OPTIONS]
```

- Use the `--key-id` switch to extract the policy from a key stored in the KMS.
- Use the `--key-file` switch to extract the policy from a Key exported as TTLV.

**Usage:**

```sh
 ckms cc policy binary [OPTIONS]
```

**Options:**

```sh
  -i, --key-id <KEY_ID>
          The public or private master key ID if the key is stored in the KMS

  -f, --key-file <KEY_FILE>
          If `key-id` is not provided, the file containing the public or private master key in TTLV format

  -p, --policy <POLICY_BINARY_FILE>
          The output binary policy file

          [default: policy.bin]

  -h, --help
          Print help (see a summary with '-h')
```

## help

Print the help message or the help of the given subcommand(s).

```sh
ckms cc policy help [SUBCOMMAND]
```
