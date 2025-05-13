The KMS server can start in authenticated or non-authenticated mode (the default).

## Non-authenticated mode

In non-authenticated mode, the server maps all requests to the default user, configured using
the `--default-username` option (or the `KMS_DEFAULT_USERNAME` environment variable). This user will
default to `admin` if not set.

```sh
--default-username <DEFAULT_USERNAME>
    The default username to use when no authentication method is provided

    [env: KMS_DEFAULT_USERNAME=]
    [default: admin]
```

## Authenticated mode

In authenticated mode, the server requires authentication for all requests. The authentication
method can be either (one of them is enough):

- a TLS client certificate and the server will extract the username from the certificate's subject
  common name (CN)
- or using native TLS combined with [Open ID-compliant](https://openid.net/) JWT access tokens or TLS client certificates. The server extracts from the JWT token the username from the token's subject (sub) claim
- an API token passed in the `Authorization` header configured both at the client and server
  side (the user being `default-username`)

The server can be configured to use multiple authentication methods concurrently:

- if the server is started with TLS client certificate authentication, the client MUST provide a
  valid certificate issued by the authority certificate provided by the server ;
- if server only provides JWT and API token authentication, client MUST provide a valid JWT token OR
  an API token in the `Authorization` header. Server will first try to authenticate using the JWT
  token, then the API token if JWT token is not provided.

At the end, if the `--force-default-username` option (or the `KMS_FORCE_DEFAULT_USERNAME`
environment
variable) is set, the server still performs the authentication but maps all requests to the default
username.

### Authenticating using TLS client certificates

The server must be started using TLS, and the certificate used to verify the clients' certificate
must be provided in PEM format using the `--authority-cert-file` option.

!!! info "Example client TLS authentication."

=== "Docker"

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
        --https-p12-file kms.server.p12  --https-p12-password password \
        --authority-cert-file verifier.cert.pem
    ```

=== "Cosmian CLI"

    The default configuration file is located at `~/.cosmian/cosmian.toml` where ~ is your home folder and by default, Cosmian CLI use no authentication when connecting the KMS.

    The configuration file should be edited manually to reflect the actual configuration of the KMS.

    ```toml
    [kms_config.http_config]
    server_url = "http://0.0.0.0:9998"
    ssl_client_pkcs12_path = "./certificates/kms.server.p12"
    ssl_client_pkcs12_password = "password"
    verified_cert = "verifier.cert.pem"
    ```

    The server extracts the username from the client certificate's subject common name (CN) unless
    the `--force-default-username` option (or the `KMS_FORCE_DEFAULT_USERNAME` environment variable) is
    set, in which case the server uses the default username.

### Authenticating using JWT access tokens

The server supports [JWT access tokens](https://jwt.io/) which are compatible
with [Open ID Connect](https://openid.net/connect/).

The server validates the JWT tokens signatures using the token
issuer [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517.) that is pulled on
server start.

#### The JWT token

The JWT token must be passed to the endpoints of the KMS server using the HTTP Authorization header:

```sh
Authorization: Bearer <TOKEN>
```

The JWT token should contain the following claims:

- `iss`: The issuer of the token. This should be the authorization server URL.
- `sub`: The subject of the token. This should be the email address of the user.
- `aud`: The audience of the token. OPTIONAL: this should be identical to the one set on the KMS
  server.
- `exp`: The expiration time of the token. This should be a timestamp in the future.
- `iat`: The time the token was issued. This should be a timestamp in the past.

On the `cosmian` command line interface, the token is configured in the client configuration. Please
refer to the [Cosmian CLI](../cosmian_cli/index.md) for more details.

#### Configuring the KMS server for JWT authentication

The KMS server JWT authentication is configured using three command line options (or corresponding
environment variables):

!!! info "Example of JWT Configuration"

=== "Docker"

    Below is an example of a JWT configuration for the KMS server using Google as the authorization
    server.

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
        --jwt-issuer-uri=https://accounts.google.com \
        --jwks-uri=https://www.googleapis.com/oauth2/v3/certs \
        --jwt-audience=cosmian_kms
    ```

    ##### JWT issuer URI

    The issuer URI of the JWT token is called to validate the token signature.

    - server option: `--jwt-issuer-uri <JWT_ISSUER_URI>`
    - env. variable: `KMS_JWT_ISSUER_URI=[<JWT_ISSUER_URI>]`

    ##### JWKS URI

    The optional JWKS (JSON Web Key Set) URI of the JWT token is called to retrieve the keyset on server
    start.
    Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set.

    - server option: `--jwks-uri <JWKS_URI>`
    - env. variable: `KMS_JWKS_URI=[<JWKS_URI>]`

    ##### JWT audience

    The KMS server validates the JWT `aud` claim against this value if set

    - server option: `--jwt-audience <JWT_AUDIENCE>`
    - env. variable: `KMS_JWT_AUDIENCE=[<JWT_AUDIENCE>]`

    #### Support for concurrent Identity Providers

    The Cosmian KMS server supports concurrent identity providers. To handle multiple identity
    providers concurrently, repeat each parameter (`jwt-issuer-uri`, `jwks-uri` and optionally
    `jwt-audience`), keeping them in the same order.

    Example:

    ```shell
    --jwt-issuer-uri=https://accounts.google.com \
    --jwks-uri=https://www.googleapis.com/oauth2/v3/certs \
    --jwt-audience=cosmian_kms \
    --jwt-issuer-uri=https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/ \
    --jwks-uri=https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys \
    --jwt-audience=<CLIENT_ID>
    ```

    #### Common Identity Providers

    ##### Google ID tokens

    Use the following options to configure the KMS server for Google ID tokens:

    ```sh
    --jwt-issuer-uri=https://accounts.google.com
    --jwks-uri=https://www.googleapis.com/oauth2/v3/certs
    ```

    ##### Auth0

    Use the following options to configure the KMS server for Auth0:

    ```sh
    --jwt-issuer-uri=https://<your-tenant>.<region>.auth0.com/
    --jwks-uri=https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json
    ```

    Note: the `/` is mandatory at the end of the issuer URL; if not present the `iss` will not validate

    ##### Google Firebase

    Use the following options to configure the KMS server for Google Firebase:

    ```sh
    --jwt-issuer-uri=https://securetoken.google.com/<YOUR-PROJECT-ID>
    --jwks-uri=https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com
    ```

    ##### Okta

    Use the following options to configure the KMS server for Okta:

    ```sh
    --jwt-issuer-uri=https://<OKTA_TENANT_NAME>.com
    --jwks-uri=https://<OKTA_TENANT_NAME>.com/oauth2/v1/keys
    --jwt-audience=<OKTA_CLIENT_ID>
    ```

    ##### Microsoft Entra ID

    Use the following options to configure the KMS server for Microsoft Entra ID:

    ```sh
    --jwt-issuer-uri=https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/
    --jwks-uri=https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys
    --jwt-audience=<CLIENT_ID>
    ```

    ### Authenticating using an API Token

    The server can be configured to authenticate using an API token passed in the `Authorization`
    header.

    To proceed, follow these steps:

    - run Cosmian KMS server without API token authentication
    - generate a symmetric key and export it from the server
    - restart the server with the `--api-token-id` option
    - configure `cosmian` client with a `access_token` containing the API token in base64.

    To generate a new API token, use the `cosmian` CLI and save the symmetric key unique identifier (<
    SYMMETRIC_KEY_ID>):

    ```sh
    cosmian kms sym keys create
    ```

    Then export the symmetric key content in base64:

    ```sh
    cosmian kms sym keys export -k <SYMMETRIC_KEY_ID> f base64 api_token.base64
    ```

    Reconfigure `cosmian` client with the previous base64 encoded key as `access_token`.
    Your `cosmian` is now ready to authenticate using the API token.

    And finally, restart the server with the `--api-token-id` option.

    ```sh
    --api_token_id <SYMMETRIC_KEY_ID>
    ```

=== "Cosmian CLI"

    When authenticating using OAuth2 or Open ID Connect, the oauth2_conf field should be set
    in the configuration file to provide the necessary information to first authenticate to Identity Provider
    and get a token to authenticate to the KMS server.

    Getting a Token from an Identity Provider is performed using the cosmian kms login command.
    The token will be saved in the cosmian configuration file.
    To remove the token, use the cosmian kms logout command.

    The oauth2_conf field is a TOML object with the following fields:

        client_id: the client ID to use when authenticating to the Identity Provider
        client_secret: the client secret to use when authenticating to the Identity Provider
        authorize_url: the URL to use when authorizing the client
        token_url: the URL to use when requesting an access token
        scopes: the optional list of scopes to request when authenticating to the KMS server

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

    When you run the cosmian kms login command, the CLI will provide a URL for you to open in your browser.
    This URL initiates the login flow and sends the user token back to the CLI using a
    redirect_url set to a local URL (http://localhost/), as the CLI runs on your local machine.
    Ensure that your Identity Provider configuration permits this type of URL.
