
The KMS server provides an authentication system using [JWT access tokens](https://jwt.io/)  compatible with [Open ID Connect](https://openid.net/connect/).

JWT tokens are validated using the token issuer [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517.)


## Client side

The JWT token must be passed to the `/kmip_2_1` endpoint of the KMS server using the HTTP Authorization header:

```
Authorization: Bearer <TOKEN>
```

The JWT token should contain the following claims:

- `iss`: The issuer of the token. This should be the authorization server URL.
- `sub`: The subject of the token. This should be the email address of the user.
- `aud`: The audience of the token. OPTIONAL: this should be identical to the one set on the KMS server.
- `exp`: The expiration time of the token. This should be a timestamp in the future.
- `iat`: The time the token was issued. This should be a timestamp in the past.


On the `cKMS` command line interface, the token is configured in the client configuration. Please refer to the [CLI documentation](cli/cli.md) for more details.

## KMS server side

The KMS server JWT authentication is configured using the following three command line options (or corresponding environment variables):

### JWT issuer URI

 - server option: `--jwt-issuer-uri <JWT_ISSUER_URI>`
 - env. variable: `KMS_JWT_ISSUER_URI=<JWT_ISSUER_URI>`

 The issuer URI of the JWT token.

##### Auth0    
The delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`

Note: the `/` is mandatory at the end of the URL; if not present the `iss` will not validate

##### Google ID tokens
Use `https://accounts.google.com`

##### Google Firebase
Use `https://securetoken.google.com/<YOUR-PROJECT-ID>`

##### Okta
Use `https://OKTA_TENANT_NAME.com`

### JWKS URI

 - server option: `--jwks-uri <JWKS_URI>`
 - env. variable: `KMS_JWKS_URI=<JWKS_URI>`

The optional JWKS (JSON Web Key Set) URI of the JWT token that is called to retrieve the keyset on server start.
Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set.

##### Auth0    
Use `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`

##### Google ID tokens
Use `https://www.googleapis.com/oauth2/v3/certs`

##### Google Firebase
Use `https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com`

##### Okta
Use `https://<OKTA_TENANT_NAME>.com`

### JWT audience

 - server option: `--jwt-audience <JWT_AUDIENCE>`
 - env. variable: `KMS_JWT_AUDIENCE=<JWT_AUDIENCE>`

The optional audience of the JWT token
      
TheKMS server will validate the JWT `aud` claim against this value if set

