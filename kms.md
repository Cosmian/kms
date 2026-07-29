# Using Eviden KMS as a Vault backend for your SPIRE server

This is a **getting-started for SPIRE operators**. It explains how to point *your
own* SPIRE server at an already-running **Eviden KMS** that exposes a
HashiCorp Vault-compatible API. You do **not** need any access to the KMS host:
you only edit your SPIRE server configuration and provide credentials your KMS
administrator gives you.

Eviden KMS is a drop-in replacement for the Vault endpoints SPIRE relies on, so
SPIRE's built-in `UpstreamAuthority "vault"` and `KeyManager "vault"` plugins
work with **no code changes** — only configuration.

```text
your SPIRE server ──vault_addr──▶ Eviden KMS  (/v1/auth/*, /v1/pki/*, /v1/transit/*)
```

You talk **only** to the KMS — it handles authentication internally, so there is
no other service for you to connect to or configure.

---

## 1. What to request from your KMS administrator

Ask your administrator for these four items:

| Item | Example | Used for |
|------|---------|----------|
| **KMS base URL** | `https://poc-mcds.cosmian.dev` | SPIRE `vault_addr` |
| **KMS CA certificate** (PEM) | `kms-ca.crt` | So SPIRE trusts the KMS TLS certificate |
| **AppRole `role_id`** | `699b480e-…` (UUID) | Your machine "username" (stable) |
| **AppRole `secret_id`** | `a1b2c3…` | Your machine "password" (rotatable) |

> **You cannot create AppRoles yourself** — that requires KMS administrator
> privileges. Your administrator creates an AppRole named
> after your service (e.g. `spire-prod`) and hands you its `role_id` and a
> freshly minted `secret_id`. The AppRole **name** becomes your isolated key
> namespace on the KMS: another tenant's AppRole can never read, sign with, or
> delete your keys.

Your SPIRE server only ever connects to the KMS URL above — there is no other
endpoint for you to reach or configure.

Copy the CA certificate somewhere your SPIRE server can read it, e.g.
`/etc/spire/server/kms-ca.crt`.

---

## 2. Provide your credentials to SPIRE

The SPIRE `vault` plugins read the AppRole credentials from environment
variables, so you never hard-code the `secret_id` in a config file:

```bash
export VAULT_APPROLE_ID="<role_id>"
export VAULT_APPROLE_SECRET_ID="<secret_id>"
```

Set these in the environment of the SPIRE server process (systemd unit,
container env, etc.).

---

## 3. Configure your SPIRE server

Add a `vault` upstream authority to your SPIRE server configuration
(`server.conf`). This lets SPIRE ask the KMS to sign its intermediate CA.

```hcl
server {
    # … your existing trust_domain, data_dir, ca_ttl, etc. …

    UpstreamAuthority "vault" {
        plugin_data {
            # The KMS base URL your administrator gave you.
            vault_addr   = "https://poc-mcds.cosmian.dev"

            # The KMS CA certificate, so SPIRE trusts the TLS connection.
            ca_cert_path = "/etc/spire/server/kms-ca.crt"

            # Authenticate with AppRole. Credentials are read from the
            # VAULT_APPROLE_ID / VAULT_APPROLE_SECRET_ID environment variables.
            approle_auth {
                approle_auth_mount_point = "approle"
            }

            # PKI mount used by the KMS (default: "pki").
            pki_mount_point = "pki"
        }
    }
}
```

### Optional: store SPIRE's own keys in the KMS (Transit)

If you also want SPIRE to keep its private keys in the KMS instead of on local
disk, add the `KeyManager "vault"` plugin. Point its transit engine at the KMS
transit mount (default: `transit`):

```hcl
    KeyManager "vault" {
        plugin_data {
            vault_addr          = "https://poc-mcds.cosmian.dev"
            ca_cert_path        = "/etc/spire/server/kms-ca.crt"
            approle_auth {
                approle_auth_mount_point = "approle"
            }
            transit_engine_path = "transit"
            key_name            = "spire-server-key"
        }
    }
```

> Field names follow SPIRE's upstream `hashicorp_vault` KeyManager plugin. Keys
> created through Transit are **non-exportable** by design — the private key
> never leaves the KMS.

Restart your SPIRE server (on your side) to apply the configuration.

---

## 4. Verify connectivity (read-only checks)

Before starting SPIRE, confirm your credentials and the KMS URL work. These
commands are safe and require no admin rights.

Exchange your AppRole credentials for a token:

```bash
curl --cacert /etc/spire/server/kms-ca.crt \
  -X POST -H 'Content-Type: application/json' \
  -d "{\"role_id\":\"${VAULT_APPROLE_ID}\",\"secret_id\":\"${VAULT_APPROLE_SECRET_ID}\"}" \
  https://poc-mcds.cosmian.dev/v1/auth/approle/login
```

A `200` response with `auth.client_token` (an `hvs.…` value) means your
credentials are valid. Save that token to list the keys you own:

```bash
TOKEN="hvs.xxxxx"   # from the response above
curl --cacert /etc/spire/server/kms-ca.crt \
  -H "X-Vault-Token: ${TOKEN}" \
  https://poc-mcds.cosmian.dev/v1/transit/keys
```

---

## 5. Troubleshooting (client side)

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `403` on `/v1/auth/approle/login` | Wrong or expired `role_id` / `secret_id` | Re-check the values; ask your admin to mint a fresh `secret_id`. |
| `403` on `/v1/transit/*` or `/v1/pki/*` | Missing, invalid, or expired `X-Vault-Token` | Log in again to get a new token. |
| `404` fetching another tenant's key | Cross-tenant isolation (expected) | You can only see keys owned by your AppRole. |
| `502 Bad Gateway` on `/v1/auth/*` | A KMS-side authentication problem | Not something you can fix — contact your KMS administrator. |
| TLS / certificate verification error | Wrong or missing CA certificate | Use the exact CA certificate the admin provided; verify the URL host matches the certificate. |

---

## See also

- Full integration reference (architecture, endpoints, flows):
  [`documentation/docs/integrations/spire_spiffe.md`](documentation/docs/integrations/spire_spiffe.md).
- Operator reference configuration (run by whoever operates the KMS — not needed
  on the SPIRE side): [`kms.toml`](kms.toml).
