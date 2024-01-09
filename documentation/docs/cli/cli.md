The `ckms` binary is a command line interface (CLI) used to manage cryptographic objects inside the KMS.

!!! info "Download ckms"
    Please download the latest version of the CLI for your Operating System from the [Cosmian public packages repository](https://package.cosmian.com/kms/4.10.1/)

#### Configuration

The CLI expects a configuration file to be located at `~/.cosmian/kms.json` where `~` is your home folder.

The configuration file is created automatically when the CLI is used for the first time with the following values

```json
{
  "kms_server_url": "http://localhost:9998",
}
```

The configuration file should be edited manually to reflect the actual configuration of the KMS.

- `kms_server_url` is MANDATORY and is the URL of the KMS server
- `kms_access_token` is OPTIONAL and is the access token used to authenticate to the KMS server.
- `ssl_client_pkcs12_path`: is OPTIONAL and is the path to the PKCS12 file containing the client certificate and private key to use when authenticating to a KMS server using a certificate.
- `ssl_client_pkcs12_password`: is OPTIONAL and is the password to open the PKCS12 file when authenticating to the KMS server using a certificate.
- `kms_database_secret` is OPTIONAL and is the base 64 encoded secret to use when connecting to a KMS using an encrypted database
- `accept_invalid_certs` is OPTIONAL and should be set to "true" to allow the CLI to connect to a KMS using an "invalid" certificate, such as a self-signed SSL certificate. Useful to run tests with a self-signed certificate.
- `verified_cert` contains the verified PEM TLS certificate used for certificate pinning

Here is an example configuration with TLS authentication and an encrypted database:

```json
{
  "kms_server_url":"https://kms.acme.com:9999",
  "ssl_client_pkcs12_path":"./certificates/john.doe.acme.p12",
  "ssl_client_pkcs12_password":"pkcs12_password",
  "kms_database_secret":"eyJncm91cF9pZCI6MjkzMjY3MjM2NDU3ODgyMjIzMjM0NDY2MjkxNTY2NDk5Nzc0NTk1LCJrZXkiOlsyMTgsNDIsMTkzLDE4Myw1OSwyMzQsMTY3LDE3Niw4OCwxNjYsMjUyLDYyLDk5LDU4LDM0LDUxLDE1Nyw5NiwyMjEsMjE1LDIwMSwxOTcsODYsOTksMTI1LDIxMSw2Niw0MCw0MiwyNDYsMTgzLDg1XX0="
}
```

#### Usage examples

Many usage examples are provided with descriptions of the various KMIP 2.1 [operations](../kmip_2_1/operations.md).
