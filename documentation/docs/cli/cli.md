# Cosmian KMS Command Line Interface (CLI)

Cosmian KMS can be managed using the `ckms` command line interface (CLI) or its graphical
client `ckms_gui`.

!!! info "Download ckms and ckms_gui"

    Please download the latest versions for your Operating System from
    the [Cosmian public packages repository](https://package.cosmian.com/kms/4.19.3/)
    See below for installation instructions.

## Installation

{!cli/cli_prerequisites.md!}


## Configuring the clients

Both clients - and the PKCS#11 provider library - expect a configuration file to be located
at `~/.cosmian/kms.json` where `~` is your home folder.

An alternate location can be used by setting the `KMS_CLI_CONF_ENV` environment
variable.

A minimum configuration file is created automatically when the CLI is used for the
first time with the following values

```json
{
  "kms_server_url": "http://localhost:9998"
}
```

The configuration file should be edited manually to reflect the actual
configuration of the KMS.

- `kms_server_url` is MANDATORY and is the URL of the KMS server
- `kms_access_token` is OPTIONAL and is the access token used to authenticate to
  the KMS server.
- `ssl_client_pkcs12_path`: is OPTIONAL and is the path to the PKCS12 file
  containing the client certificate and private key to use when authenticating
  to a KMS server using a certificate.
- `ssl_client_pkcs12_password`: is OPTIONAL and is the password to open the
  PKCS12 file when authenticating to the KMS server using a certificate.
- `oauth2_conf`: is OPTIONAL and is the OAuth2 configuration (
  see [below](#oauth2oidc-configuration))
  to use when authenticating to the KMS server using OAuth2 or Open ID Connect.
- `kms_database_secret` is OPTIONAL and is the base 64 encoded secret to use
  when connecting to a KMS using an encrypted database
- `accept_invalid_certs` is OPTIONAL and should be set to "true" to allow the
  CLI to connect to a KMS using an "invalid" certificate, such as a self-signed
  SSL certificate. Useful to run tests with a self-signed certificate.
- `verified_cert` contains the verified PEM TLS certificate used for certificate
  pinning
- `gmail_api_conf` is OPTIONAL and contains information about the configured
  service account used to fetch Gmail API and handle easily S/MIME elements (identities, key pairs)
  (see [below](#smime-gmail-service-account-configuration))

Here is an example configuration with TLS authentication and a client-side encrypted
database:

```json
{
  "kms_server_url": "https://kms.acme.com:9999",
  "ssl_client_pkcs12_path": "./certificates/john.doe.acme.p12",
  "ssl_client_pkcs12_password": "pkcs12_password",
  "kms_database_secret": "eyJncm91cF9pZCI6MjkzMjY3MjM2NDU3ODgyMjIzMjM0NDY2MjkxNTY2NDk5Nzc0NTk1LCJrZXkiOlsyMTgsNDIsMTkzLDE4Myw1OSwyMzQsMTY3LDE3Niw4OCwxNjYsMjUyLDYyLDk5LDU4LDM0LDUxLDE1Nyw5NiwyMjEsMjE1LDIwMSwxOTcsODYsOTksMTI1LDIxMSw2Niw0MCw0MiwyNDYsMTgzLDg1XX0="
}
```

## OAuth2/OIDC configuration

When authenticating using OAuth2 or Open ID Connect, the
`oauth2_conf` field should be set in the configuration file to provide the necessary
information to first authenticate to Identity Provider and get a token to authenticate
to the KMS server.

Getting a Token from an Identity Provider is performed using the `ckms login` command. The token
will be saved in the `ckms` configuration file. To remove the token, use the `ckms logout` command.

The `oauth2_conf` field is a JSON object with the following fields:

- `client_id`: the client ID to use when authenticating to the Identity Provider
- `client_secret`: the client secret to use when authenticating to the Identity Provider
- `authorize_url`: the URL to use when authorizing the client
- `token_url`: the URL to use when requesting an access token
- `scopes`: the optional list of scopes to request when authenticating to the KMS server

Example Google Identity Provider configuration:

```json
{
  "kms_server_url": "https://kms.acme.com:9999",
  "oauth2_conf": {
    "client_id": "99999999-abababababababababab.apps.googleusercontent.com",
    "client_secret": "G0ABCD-aAbBcDeFgHiJkLmNoPqRsTuVwXyZ",
    "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_url": "https://oauth2.googleapis.com/token",
    "scopes": [
      "openid",
      "email"
    ]
  }
}
```

## S/MIME Gmail service account configuration

When using S/MIME, the `gmail_api_conf` field should be set in the configuration file to provide
the necessary information about the configured service account to interact with Gmail API, and
handle
identities and keypairs easily from the ckms.

This configuration is mandatory for `ckms google` subcommands.

The `gmail_api_conf` field is a JSON object with the following fields:

- `account_type`
- `project_id`
- `private_key_id`
- `private_key`
- `client_email`
- `client_id`
- `auth_uri`
- `token_uri`
- `auth_provider_x509_cert_url`
- `client_x509_cert_url`
- `universe_domain`

I can be retrieved directly from a JSON file downloaded from Google interface when creating
and configuring the service account (following Google documentation).

Example:

```json
{
  "kms_server_url": "https://kms.acme.com:9999",
  "gmail_api_conf": {
    "account_type": "service_account",
    "project_id": "project_id",
    "private_key_id": "abc123abc123abc123abc123abc123abc123",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
    "client_email": "xxx@yyyy.iam.gserviceaccount.com",
    "client_id": "12345678901234567890",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/xxx%40yyyy.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
  }
}
```

## Usage

Usage examples of the CLI are provided with descriptions of the various KMIP
2.1 [operations](../kmip_2_1/operations.md).

The GUI version offers the same features as the CLI, but with a graphical user interface.
