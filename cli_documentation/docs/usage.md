# Usage

```sh
Command Line Interface used to manage the Cosmian KMS server.

If any assistance is needed, please either visit the Cosmian technical documentation at https://docs.cosmian.com
or contact the Cosmian support team on Discord https://discord.com/invite/7kPMNtHpnz


Usage: ckms [OPTIONS] <COMMAND>

Commands:
  access-rights  Manage the users' access rights to the cryptographic objects
  attributes     Get/Set/Delete/Modify the KMIP object attributes
  azure          Support for Azure specific interactions
  aws            Support for AWS specific interactions
  bench          Run benchmarks using criterion for statistical analysis.
  cc             Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data
  fpe            Manage FPE keys and perform FPE encryption/decryption through KMIP Encrypt/Decrypt
  pqc            Manage post-quantum keys (ML-KEM, ML-DSA, Hybrid KEM, SLH-DSA). Encapsulate, decapsulate, sign, and verify
  tokenize       Anonymization utilities: hash, noise, word masking, pattern masking, aggregation, and scaling
  certificates   Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
  derive-key     Derive a new key from an existing key
  ec             Manage elliptic curve keys. Encrypt and decrypt data using ECIES
  google         Manage google elements. Handle key pairs and identities from Gmail API
  locate         Locate cryptographic objects inside the KMS
  login          Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.
  logout         Logout from the Identity Provider
  hash           Hash arbitrary data.
  mac            MAC utilities: compute or verify a MAC value.
  rng            RNG utilities: retrieve random bytes or seed RNG
  server         Server-related commands
  rsa            Manage RSA keys. Encrypt and decrypt data using RSA keys
  opaque-object  Create, import, export, revoke and destroy Opaque Objects
  secret-data    Create, import, export and destroy secret data
  sym            Manage symmetric keys. Encrypt and decrypt data
  markdown       Regenerate the CLI documentation in Markdown format
  configure      Configure the KMS CLI (create ckms.toml)
  help           Print this message or the help of the given subcommand(s)

Options:
  -c, --conf-path <CONF_PATH>
          Configuration file location

          This is an alternative to the env variable `CKMS_CONF_PATH`. Takes precedence over `CKMS_CONF_PATH` env variable.

          [env: CKMS_CONF_PATH=]

      --url <URL>
          The URL of the KMS

          [env: KMS_DEFAULT_URL=]

      --print-json
          Output the KMS JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint

      --accept-invalid-certs
          Allow to connect using a self-signed cert or untrusted cert chain

          `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server running an invalid or insecure SSL certificate

  -H, --header <NAME: VALUE>
          Add a custom HTTP header to every request sent to the KMS server.

          The header must be specified in `"Name: Value"` format, matching the
          curl `-H` / `--header` convention. This option may be repeated to add
          multiple headers.

          The environment variable `CLI_HEADER` may also be used; separate
          multiple headers with a newline character.

          Example: `--header "cf-access-token: <token>"`

          [env: CLI_HEADER=]

      --proxy-url <PROXY_URL>
          The proxy URL:
            - e.g., `https://secure.example` for an HTTP proxy
            - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy

          [env: CLI_PROXY_URL=]

      --proxy-basic-auth-username <PROXY_BASIC_AUTH_USERNAME>
          Set the Proxy-Authorization header username using Basic auth.

          [env: CLI_PROXY_BASIC_AUTH_USERNAME=]

      --proxy-basic-auth-password <PROXY_BASIC_AUTH_PASSWORD>
          Set the Proxy-Authorization header password using Basic auth.

          [env: CLI_PROXY_BASIC_AUTH_PASSWORD=]

      --proxy-custom-auth-header <PROXY_CUSTOM_AUTH_HEADER>
          Set the Proxy-Authorization header to a specified value.

          [env: CLI_PROXY_CUSTOM_AUTH_HEADER=]

      --proxy-exclusion-list <PROXY_EXCLUSION_LIST>
          The No Proxy exclusion list to this Proxy

          [env: CLI_PROXY_NO_PROXY=]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
