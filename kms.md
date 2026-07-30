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
  Admin ops   ──:8443──────▶    │  Auth-verifier :8443  (AppRoles) │
                                └──────────────────────────────────┘
```

- **KMS** (`https://poc-mcds.cosmian.dev`) handles cryptographic operations
  (transit keys, PKI signing) and proxies AppRole **login** requests.
- **Auth-verifier** (`https://poc-mcds.cosmian.dev:8443`) manages identities
  (AppRole CRUD). You connect to it directly to create/manage AppRoles.

---

## Prerequisites

### Download the auth-verifier CA certificate

The auth-verifier uses a private CA. Extract it from the TLS handshake:

```bash
openssl s_client -connect poc-mcds.cosmian.dev:8443 -showcerts </dev/null 2>/dev/null \
  | python3 -c "
import sys, re
certs = re.findall(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
                   sys.stdin.read(), re.DOTALL)
print(certs[1])
" > auth-ca.pem

# Verify
openssl x509 -in auth-ca.pem -noout -subject
```

> The auth-verifier sends its CA certificate as the second certificate in the
> TLS handshake chain. This command extracts it and saves it to `auth-ca.pem`.

---

## 1. Create your AppRole

AppRoles are managed **directly** on the auth-verifier. You must authenticate
as admin (HTTP Basic Auth) to get a session cookie, then use that cookie for
all management operations.

### Option A — using `ckms` (recommended)

Install `ckms` from the [Cosmian releases page](https://github.com/Cosmian/kms/releases), then:

```bash
export CKMS_VAULT_AUTH_URL="https://poc-mcds.cosmian.dev:8443"
export CKMS_VAULT_AUTH_CA_CERT="auth-ca.pem"
export CKMS_VAULT_ADMIN_USER="admin"
export CKMS_VAULT_ADMIN_PASSWORD="change_me"

# Create the role (1-hour token TTL)
ckms vault approle create-role spire-prod --token-ttl 3600

# Read the stable role_id
export VAULT_APPROLE_ID=$(ckms vault approle get-role-id spire-prod)
echo "role_id: $VAULT_APPROLE_ID"

# Mint a secret_id — regenerate this each time SPIRE restarts
export VAULT_APPROLE_SECRET_ID=$(
  ckms vault approle generate-secret-id spire-prod \
    | awk '/^secret_id:/{print $2}')
echo "secret_id: $VAULT_APPROLE_SECRET_ID"
```

### Option B — using `curl` only (no `ckms` required)

The admin login requires **HTTP Basic Auth** + `Content-Type: application/json`:

```bash
AUTH_URL="https://poc-mcds.cosmian.dev:8443"
AUTH_CA="auth-ca.pem"
ADMIN_USER="admin"
ADMIN_PASSWORD="change_me"
ROLE_NAME="spire-prod"
COOKIE_JAR="/tmp/auth-admin-cookies.txt"

# Step 1 — Get an admin session cookie
curl -s -c "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -u "$ADMIN_USER:$ADMIN_PASSWORD" \
  -H "Content-Type: application/json" -d "{}" \
  "$AUTH_URL/login?realm=_"
echo ""

# Step 2 — Create the AppRole
curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -H "Content-Type: application/json" \
  -d '{"token_ttl":3600,"secret_id_ttl":0,"token_policies":["default"],"bind_secret_id":true}' \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME"
echo ""

# Step 3 — Read the stable role_id
export VAULT_APPROLE_ID=$(curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME/role-id" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
echo "role_id: $VAULT_APPROLE_ID"

# Step 4 — Generate a secret_id
SECRET_RESP=$(curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -H "Content-Type: application/json" -d '{"ttl":0,"num_uses":0}' \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME/secret-id")
export VAULT_APPROLE_SECRET_ID=$(echo "$SECRET_RESP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
echo "secret_id: $VAULT_APPROLE_SECRET_ID"
```

> **Session duration**: the `_ea_` admin cookie is valid for the session
> duration configured on the auth-verifier (default: several hours). Rerun
> Step 1 if subsequent calls return `401 Session error`.
>
> **Key isolation**: the AppRole name (`spire-prod`) becomes your isolated
> namespace on the KMS. Another tenant's AppRole can never read, sign with,
> or delete your transit keys or PKI certificates.

---

## 2. Verify your AppRole credentials (read-only)

Before configuring SPIRE, confirm your credentials work end-to-end:

```bash
KMS_URL="https://poc-mcds.cosmian.dev"

# Exchange AppRole credentials for a KMS token
TOKEN=$(curl -s \
  -X POST -H "Content-Type: application/json" \
  -d "{\"role_id\":\"$VAULT_APPROLE_ID\",\"secret_id\":\"$VAULT_APPROLE_SECRET_ID\"}" \
  "$KMS_URL/v1/auth/approle/login" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
echo "Token: $TOKEN"

# Validate the token and inspect your identity
curl -s -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/auth/token/lookup-self"
echo ""

# List transit keys owned by your AppRole (empty on first use)
curl -s -H "X-Vault-Token: $TOKEN" "$KMS_URL/v1/transit/keys"
echo ""
```

A `200` response with `"entity_id": "spire-prod"` confirms your credentials
and KMS connectivity are working.

---

## 3. Configure your SPIRE server

Add a `vault` upstream authority to `server.conf`:

```hcl
server {
    # … your existing trust_domain, data_dir, ca_ttl, etc. …

    UpstreamAuthority "vault" {
        plugin_data {
            # KMS base URL (not the auth-verifier URL).
            vault_addr = "https://poc-mcds.cosmian.dev"

            # KMS uses a Let's Encrypt certificate — trusted by default.
            # Provide ca_cert_path only if using a private CA.
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
            vault_addr = "https://poc-mcds.cosmian.dev"
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

### Rotate secret_id (before each SPIRE restart)

```bash
# Option A — ckms
export VAULT_APPROLE_SECRET_ID=$(
  ckms vault approle generate-secret-id spire-prod \
    | awk '/^secret_id:/{print $2}')

# Option B — curl (reuse cookie jar from Step 1)
SECRET_RESP=$(curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  -X POST -H "Content-Type: application/json" -d '{"ttl":0,"num_uses":0}' \
  "$AUTH_URL/auth/approle/role/$ROLE_NAME/secret-id")
export VAULT_APPROLE_SECRET_ID=$(echo "$SECRET_RESP" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
```

### List roles

```bash
# Option A — ckms
ckms vault approle list-roles

# Option B — curl
curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" \
  "$AUTH_URL/auth/approle/role?list=true"
```

### Delete a role

```bash
# Option A — ckms
ckms vault approle delete-role spire-prod

# Option B — curl
curl -s -b "$COOKIE_JAR" --cacert "$AUTH_CA" -X DELETE \
  "$AUTH_URL/auth/approle/role/spire-prod"
```

---

## 5. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `403` on `/v1/auth/approle/login` | Wrong or expired credentials | Re-check `role_id`/`secret_id`; generate a fresh `secret_id`. |
| `403` on `/v1/transit/*` or `/v1/pki/*` | Invalid or expired `X-Vault-Token` | Log in again with your AppRole to get a new token. |
| `404` fetching another tenant's key | Cross-tenant isolation (expected) | You can only see keys owned by your AppRole. |
| `401 Session error` on `:8443` admin call | Session cookie expired | Rerun the `POST /login?realm=_` step to get a fresh cookie. |
| `401 No authentication provided.` on `:8443` | Missing Basic Auth | Use `-u "$ADMIN_USER:$ADMIN_PASSWORD"` with curl. |
| `502 Bad Gateway` on `/v1/auth/*` | KMS cannot reach auth-verifier | Check KMS logs; verify auth-verifier is running at `:8443`. |

---

## See also

- [`kms_setup.sh`](kms_setup.sh) — Bash script that runs all steps above in
  one shot (`ROLE_NAME=my-spire ./kms_setup.sh`).
- Full integration reference:
  [`documentation/docs/integrations/spire_spiffe.md`](documentation/docs/integrations/spire_spiffe.md).
- KMS operator configuration: [`kms.toml`](kms.toml).
