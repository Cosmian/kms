# Try RBAC with Keycloak and OPA

This how-to guide runs the Cosmian KMS in [Mode 2 — Exclusive OPA](mode2.md) behind a real identity provider, so that you can see each [role](index.md) at work. You manage users and groups in [Keycloak](https://www.keycloak.org/), the KMS asks an [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) server to authorize each KMIP operation, and the Rego policy `test_data/opa/kms.rego` defines what every role may do.

The stack is the Docker Compose project `deploy/rbac_rego` of the repository. This page is the short version: its `README.md` also covers the KMIP requests by hand, the OPA decision log, adding users and groups, editing the policy live and switching to the enforcing mode.

!!! warning "Demo only"
    The passwords, the Keycloak realm and the TLS certificates of the stack are public demo values, and the certificates are signed by the test CA of the `test_data` submodule. Run it on a local machine only. All its ports are published on the loopback interface.

## Prerequisites

- Docker Compose v2, `bash` 4 or later, `curl` and `jq`.
- The `test_data` submodule: `git submodule update --init test_data`.
- `keycloak.localhost` resolving to the loopback address. Most systems resolve any `*.localhost` name; otherwise add `127.0.0.1 keycloak.localhost` to `/etc/hosts`. The KMS container reaches Keycloak under the same name, so the `iss` claim of a token is identical for the host and for the KMS.
- A KMS container image, built once from the repository root with `mise run build:docker --variant fips --load`.

## Start the stack

```bash
cd deploy/rbac_rego
cp .env.example .env    # demo credentials and KMS_IMAGE, the name of the image built above
docker compose up -d --wait
./verify.sh
```

`--wait` returns when OPA is running and Keycloak and the KMS are healthy. `verify.sh` gets an access token for every sample user, sends KMIP requests with it and compares each outcome with the expected decision and with a direct query to OPA. It ends with this line when everything agrees:

```text
OK: 53 checks, the KMS, the expected role matrix and OPA agree.
```

Delete the stack and the KMS data with `docker compose down -v`.

## Sample users

The Keycloak realm `kms` has one group per role, named exactly like the role, and eight users. They log in with their e-mail address and the `DEMO_USER_PASSWORD` of your `.env`.

| User | Group (role) | Domain |
| ---- | ------------ | ------ |
| `superadmin@acme.com` | `SuperAdmin` | `acme.com` |
| `admin@acme.com` | `DomainAdmin` | `acme.com` |
| `officer@acme.com` | `CryptoOfficer` | `acme.com` |
| `auditor@acme.com` | `Auditor` | `acme.com` |
| `user@acme.com` | `User` | `acme.com` |
| `norole@acme.com` | none | `acme.com` |
| `officer@globex.com` | `CryptoOfficer` | `globex.com` |
| `user@globex.com` | `User` | `globex.com` |

## Expected decisions

For a caller that does not own the key and acts in the same domain as the key. The owner of a key is always allowed, whatever its role.

| Role | Create | Get | GetAttributes | Activate |
| ---- | ------ | --- | ------------- | -------- |
| `SuperAdmin` | allow | allow | allow | allow |
| `DomainAdmin` | allow | allow | allow | allow |
| `CryptoOfficer` | allow | allow | allow | allow |
| `Auditor` | deny | allow | allow | deny |
| `User` | deny | deny | allow | deny |
| no role | deny | deny | deny | deny |

Across domains only `SuperAdmin` is allowed: `superadmin@acme.com` can `Get` a key of `globex.com`, while every other user is denied on the keys of the other domain. A denied `Get` on another user's key is reported as `Object_Not_Found`.

## How a token becomes an OPA decision

The KMS validates the Keycloak access token, then sends OPA the identity, the roles and the domain it read from the token, with the operation and the owner and domain of the target object.

| Token claim | Comes from Keycloak | Used by the KMS |
| ----------- | ------------------- | --------------- |
| `iss` | URL of the realm `kms` | Must equal the issuer of `jwt_auth_provider` |
| `aud` | Audience mapper of the client `kms-demo` | Must equal the audience of `jwt_auth_provider` (`cosmian-kms`) |
| `email` | E-mail address of the user | User identity (`sub` when the token has no `email`): the owner of a key is the user who created it |
| `roles` | Names of the groups of the user | `roles` of the OPA input |
| `as_rid` | Admin-only user attribute `domain` | `user_domain` of the OPA input (`as_rid` is an alias of `as_domain`) |

The matching server configuration is the complete fixture `test_data/configs/server/rbac/keycloak_opa.toml`. Its two relevant sections:

```toml
[idp_auth]
jwt_auth_provider = [
  "https://keycloak.localhost:8443/realms/kms,https://keycloak.localhost:8443/realms/kms/protocol/openid-connect/certs,cosmian-kms",
]

[opa]
opa_url  = "http://opa:8181"
opa_mode = "exclusive"
```

The second field of `jwt_auth_provider` is the JWKS URI of the realm, `<issuer>/protocol/openid-connect/certs` for Keycloak. The KMS requires the standard `sub` and `exp` claims and reads no claim other than the ones listed above, so another identity provider works if its access tokens carry them all.

## Known limitations

- **Encrypt and Revoke of someone else's key use the native KMS grants.** In the current server, a non-owner calling Encrypt or Revoke is not checked by OPA, even in exclusive mode: a caller that the policy would allow but that has no native grant gets `Item_Not_Found`. Get, GetAttributes and Activate are decided by OPA. `verify.sh` therefore checks Encrypt and Revoke against OPA only.
- **The Web UI is not part of the stack.** Its plain OIDC login keeps no `roles` or domain in the session. Roles reach the KMS through bearer tokens, as in this stack.
- **A user without a domain has an empty domain.** Its token carries no `as_rid` claim, so the KMS sends OPA an empty `user_domain`. `same_domain` in `kms.rego` is a plain equality test, so a user with a role but no domain is treated as a member of the empty domain and reaches every object whose domain is empty. The realm therefore makes the `domain` attribute mandatory when an administrator creates a user; give a `domain` attribute to every user you add to the realm file as well.
- **Demo security posture.** The public client `kms-demo` uses the password grant, Keycloak runs with its embedded development database and the certificates come from the public test CA. A production deployment uses the authorization code flow, a production database and its own PKI.

## See also

- [Authorization overview](index.md): role model, JWT claims and OPA input document
- [Mode 2 — Exclusive OPA (RBAC)](mode2.md) and [Mode 3 — Enforcing](mode3.md)
- [OPA + Authentication Verifier setup](opa-authverifier-setup.md)
