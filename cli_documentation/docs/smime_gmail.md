# S/MIME Gmail service account configuration

When using S/MIME, the `gmail_api_conf` field should be set in the configuration file to provide
the necessary information about the configured service account to interact with Gmail API, and
handle
identities and keypairs easily from the cosmian kms.

This configuration is mandatory for `cosmian kms google` subcommands.

The `gmail_api_conf` field is a TOML object with the following fields:

- `type`
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

I can be retrieved directly from a TOML file downloaded from Google interface when creating
and configuring the service account (following Google documentation).

Example:

```toml
[kms_config.http_config]
server_url = "http://127.0.0.1:9998"

[kms_config.gmail_api_conf]
type = "service_account"
project_id = "project_id"
private_key_id = "abc123abc123abc123abc123abc123abc123"
private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
client_email = "xxx@yyyy.iam.gserviceaccount.com"
client_id = "12345678901234567890"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/xxx%40yyyy.iam.gserviceaccount.com"
universe_domain = "googleapis.com"
```
