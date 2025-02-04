# Authentication

Cosmian CLI can connect both to KMS and Findex server and requires different authentication methods:

The default configuration file is located at `~/.cosmian/cosmian.toml` where `~` is your home folder and by default,
Cosmian CLI use no authentication when connecting the KMS and Findex server.

An alternate location can be used by setting the `COSMIAN_CLI_CONF` environment
variable.

A minimum configuration file is created automatically when the CLI is used for the
first time with the following values

```toml
[kms_config.http_config]
server_url = "http://0.0.0.0:9998"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
```

The configuration file should be edited manually to reflect the actual
configuration of the products KMS and Findex server.
Each product has its own `http_config` configuration.

- `server_url` is MANDATORY and is the URL of the server
- `access_token` is OPTIONAL and is the access token used to authenticate to
  the server.
- `ssl_client_pkcs12_path`: is OPTIONAL and is the path to the PKCS12 file
  containing the client certificate and private key to use when authenticating
  to the server using a certificate.
- `ssl_client_pkcs12_password`: is OPTIONAL and is the password to open the
  PKCS12 file when authenticating to the server using a certificate.
- `oauth2_conf`: is OPTIONAL and is the OAuth2 configuration (
  see [OAuth2/OIDC configuration](./authentication.md))
  to use when authenticating to the server using OAuth2 or Open ID Connect.
- `database_secret` is OPTIONAL and is the base 64 encoded secret to use
  when connecting to the server using an encrypted database
- `accept_invalid_certs` is OPTIONAL and should be set to "true" to allow the
  CLI to connect to the server using an "invalid" certificate, such as a self-signed
  SSL certificate. Useful to run tests with a self-signed certificate.
- `verified_cert` contains the verified PEM TLS certificate used for certificate
  pinning

In addition for KMS, a service account can be used to fetch Gmail API and
handle easily S/MIME elements (identities, key pairs)
(see [S/MIME Gmail service account configuration](./smime_gmail.md))

## Example

Here is an example configuration with:

- a KMS server without authentication
- a Findex server with TLS authentication and a client-side encrypted database:

```toml
[kms_config.http_config]
server_url = "http://127.0.0.1:9998"

[findex_config.http_config]
accept_invalid_certs = true
server_url = "https://127.0.0.1:6660"
ssl_client_pkcs12_path = "./certificates/john.doe.acme.p12"
ssl_client_pkcs12_password = "pkcs12_password"
database_secret = "eyJncm91cF9pZCI6MjkzMjY3MjM2AND...Cw0MiwyANDYsMTgzLDg1XX0="
```

## OAuth2/OIDC configuration

When authenticating using OAuth2 or Open ID Connect, the
`oauth2_conf` field should be set in the configuration file to provide the necessary
information to first authenticate to Identity Provider and get a token to authenticate
to the KMS server.

Getting a Token from an Identity Provider is performed using the `cosmian kms login` command. The token
will be saved in the `cosmian` configuration file. To remove the token, use the `cosmian kms logout` command.

The `oauth2_conf` field is a TOML object with the following fields:

- `client_id`: the client ID to use when authenticating to the Identity Provider
- `client_secret`: the client secret to use when authenticating to the Identity Provider
- `authorize_url`: the URL to use when authorizing the client
- `token_url`: the URL to use when requesting an access token
- `scopes`: the optional list of scopes to request when authenticating to the KMS server

Example Google Identity Provider configuration:

```toml
[kms_config.http_config]
server_url = "http://127.0.0.1:9998"

[kms_config.http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "XXX"
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]
```

When you run the `cosmian kms login` command, the CLI will provide a URL for you to open in your browser.
This URL initiates the login flow and sends the user token back to the CLI using a `redirect_url` set to a
local URL (http://localhost/), as the CLI runs on your local machine. Ensure that your Identity Provider
configuration permits this type of URL.
