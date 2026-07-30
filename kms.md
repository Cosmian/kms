# Using Eviden KMS as a Vault backend for your SPIRE server

This is a **getting-started for customers** who operate both their SPIRE server
and the authentication service (auth-verifier). It explains how to:

1. **Provision your own AppRole** on the auth-verifier (you are the administrator)
2. **Configure SPIRE** to use the Eviden KMS as a Vault-compatible backend
3. **Verify** the end-to-end connectivity

```text
                                ┌──────────────────────────────────┐
                                │     poc-mcds.cosmian.dev         │
  SPIRE server ──vault_addr──▶  │  KMS :443  (/v1/transit, /v1/pki)│
  ckms vault  ──:8443──────▶    │  Auth-verifier :8443  (AppRoles) │
                                └──────────────────────────────────┘
```

- **KMS** (`https://poc-mcds.cosmian.dev`) handles cryptographic operations
  (transit keys, PKI signing) and proxies AppRole **login** requests.
- **Auth-verifier** (`https://poc-mcds.cosmian.dev:8443`) manages identities
  (AppRole CRUD). You connect to it directly to create/manage AppRoles.

---

## Prerequisites

### Download the auth-verifier CA certificate

The auth-verifier uses a private CA. Save it once:

```bash
curl -sk https://poc-mcds.cosmian.dev:8443/public/ca-chain \
  -o auth-ca.pem 2>/dev/null \
  || echo "Or ask the KMS operator to provide auth-ca.pem"
```

> If that endpoint is not available, the operator can share the CA certificate
> directly (`/etc/cosmian/auth-verifier/certs/auth.ca.pem` on the server).

### Install `ckms`

Download the latest `ckms` binary from the
[Cosmian releases page](https://github.com/Cosmian/kms/releases) and put it
on your `PATH`.

---

## 1. Create your AppRole

You manage AppRoles **directly** on the auth-verifier using `ckms vault approle`
commands. Set up your environment once:

```bash
export CKMS_VAULT_AUTH_URL="https://poc-mcds.cosmian.dev:8443"
export CKMS_VAULT_AUTH_CA_CERT="auth-ca.pem"
export CKMS_VAULT_ADMIN_USER="admin"
export CKMS_VAULT_ADMIN_PASSWORD="change_me"   # change on first login
```

Then create an AppRole for your SPIRE server:

```bash
# Create the role (1-hour token TTL, unlimited secret-ID lifetime)
ckms vault approle create-role spire-prod --token-ttl 3600

# Read the stable role_id — export it for use with SPIRE
export VAULT_APPROLE_ID=$(ckms vault approle get-role-id spire-prod)
echo "role_id: $VAULT_APPROLE_ID"

# Mint a secret_id — regenerate this each time SPIRE restarts
export VAULT_APPROLE_SECRET_ID=$(
  ckms vault approle generate-secret-id spire-prod \
    | awk '/^secret_id:/{print $2}')
echo "secret_id: $VAULT_APPROLE_SECRET_ID"
```

> **Key isolation**: the AppRole name (`spire-prod`) becomes your isolated
> namespace on the KMS. Another tenant's AppRole can never read, sign with,
> or delete your transit keys or PKI certificates.

---

## 2. Verify your AppRole credentials (read-only)

Before configuring SPIRE, confirm your credentials work. These calls are
safe and require no admin rights:

```bash
KMS_URL="https://poc-mcds.cosmian.dev"

# Exchange AppRole credentials for a token
TOKEN=$(curl -s \
  -X POST -H "Content-Type: application/json" \
  -d "{\"role_id\":\"$VAULT_APPROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}" \
  "$KMS_URL/v1/auth/approle/login" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
echo "Token: $TOKEN"

# Validate the token and inspect your identity
curl -s -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/auth/token/lookup-self"

# List transit keys owned by your AppRole (empty on first use)
curl -s -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/transit/keys"
```

A `200` with `entity_id: "spire-prod"` means your credentials and KMS
connectivity are working.

---

## 3. Configure your SPIRE server

Add a `vault` upstream authority to `server.conf`:

```hcl
server {
    # … your existing trust_domain, data_dir, ca_ttl, etc. …

    UpstreamAuthority "vault" {
        plugin_data {
            # KMS base URL (not the auth-verifier URL).
            vault_addr   = "https://poc-mcds.cosmian.dev"

            # KMS TLS certificate chain (Let's Encrypt — standard trust store,
            # or download from the server and reference it here).
            # ca_cert_path = "/etc/spire/server/kms-ca.crt"

            # Credentials are read from environment variables:
            #   VAULT_APPROLE_ID / VAULT_APPROLE_SECRET_ID
            approle_auth {
                approle_auth_mount_point = "approle"
            }

            # PKI mount (default: "pki").
            pki_mount_point = "pki"
        }
    }
}
```

### Optional: store SPIRE's own keys in the KMS (Transit)

```hcl
    KeyManager "vault" {
        plugin_data {
            vault_addr          = "https://poc-mcds.cosmian.dev"
            approle_auth {
                approle_auth_mount_point = "approle"
            }
            transit_engine_path = "transit"
            key_name            = "spire-server-key"
        }
    }
```

Set the environment variables, then start SPIRE:

```bash
export VAULT_APPROLE_ID="<role_id from step 1>"
export VAULT_APPROLE_SECRET_ID="<secret_id from step 1>"
spire-server run -config /etc/spire/server/server.conf
```

---

## 4. Manage AppRole credentials

```bash
# Rotate the secret_id (do this before each SPIRE restart)
export VAULT_APPROLE_SECRET_ID=$(
  ckms vault approle generate-secret-id spire-prod \
    | awk '/^secret_id:/{print $2}')

# List all your roles
ckms vault approle list-roles

# Delete a role (removes all its keys on the KMS)
ckms vault approle delete-role spire-prod
```

---

## 5. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `403` on `/v1/auth/approle/login` | Wrong or expired `role_id` / `secret_id` | Re-check the values; generate a fresh `secret_id`. |
| `403` on `/v1/transit/*` or `/v1/pki/*` | Missing, invalid, or expired `X-Vault-Token` | Log in again to get a new token. |
| `404` fetching another tenant's key | Cross-tenant isolation (expected) | You can only see keys owned by your AppRole. |
| `401` on auth-verifier admin call | Wrong admin password | Check `CKMS_VAULT_ADMIN_PASSWORD`. |
| `502 Bad Gateway` on `/v1/auth/*` | KMS cannot reach auth-verifier | Check KMS logs; verify auth-verifier is running. |
| TLS verification error (`:8443`) | Missing auth-verifier CA cert | Provide `--auth-verifier-ca-cert auth-ca.pem`. |

---

## See also

- [`kms_setup.sh`](kms_setup.sh) — Bash script that runs all steps above in
  one shot (`ROLE_NAME=my-spire ./kms_setup.sh`).
- Full integration reference (architecture, endpoints, flows):
  [`documentation/docs/integrations/spire_spiffe.md`](documentation/docs/integrations/spire_spiffe.md).
- KMS operator configuration: [`kms.toml`](kms.toml).
