
The Cosmian Key Management System (KMS) is a command line interface (CLI) used to manage cryptographic objects inside the KMS.


!!! info "Download ckms"
    Please download the latest version of the CLI for your Operating System from the [releases page]

The CLI expects a configuration file to be located at `~/.cosmian/kms.json` where `~` is your home folder.

The configuration file is created automatically when the CLI is used for the first time with the following values 
```json
{
  "kms_server_url": "http://localhost:9998",
}
```
The configuration file should be edited manually to reflect the actual configuration of the KMS.

 - `kms_server_url` is MANDATORY and is the URL of the KMS server
 - `kms_access_token` is OPTIONAL and is the access token used to authenticate to the KMS server. If the server runs without authentication, you can let `kms_access_token` be an empty string.
 - `ssl_client_pkcs12_path`: is OPTIONAL and is the path to the PKCS12 file containing the client certificate and private key to use when authenticating to a KMS using a certificate.
  - `ssl_client_pkcs12_password`: is OPTIONAL and is the password to use to open the PKCS12 file when authenticating to a KMS using a certificate.
 - `kms_database_secret` is OPTIONAL and is the base 64 encoded secret to use when connecting to a KMS using an encrypted database
 - `accept_invalid_certs` is OPTIONAL and should be set to "true" to allow the CLI to connect to a KMS using an "invalid" certificate such as a self-signed SSL certificate. For instance, it could be the case when running tests with the on-premise version.
