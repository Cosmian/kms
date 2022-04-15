


The KMS server provides a way to authenticate access, through [Access Tokens](https://auth0.com/docs/secure/tokens#access-tokens).

A valid access token is required to access the KMS REST API. The token must be carried in HTTP header `Authorization`.

The authentication is enabled if the environment variable `KMS_DELEGATED_AUTHORITY_DOMAIN` is provided when starting the KMS Docker container (see below). The variable should contain the URL of the domain i.e.
```
-e KMS_DELEGATED_AUTHORITY_DOMAIN=my_auth_domain.com
```

If the flag is not provided, the authentication is _completely_ disabled.

