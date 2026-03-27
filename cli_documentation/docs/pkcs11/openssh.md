# OpenSSH Integration

The Cosmian KMS PKCS#11 provider enables OpenSSH to use SSH keys stored in the KMS for
authentication. The **private key never leaves the KMS**: every signing operation is performed
server-side and only the signature is returned to the SSH client.

---

## How it works

1. You create an asymmetric key pair in the KMS and tag it with `ssh-auth`.
2. You export the corresponding public key and add it to `~/.ssh/authorized_keys` on every server
   you want to reach.
3. You tell OpenSSH to use the Cosmian PKCS#11 library (`libcosmian_pkcs11.so`) as its hardware
   security token provider.
4. When you `ssh` to a server, OpenSSH calls `C_Sign` through the library, which forwards the
   signing request to the KMS. Only the signature comes back.

---

## Supported algorithms

| Algorithm | Key size / curve | PKCS#11 mechanism |
|---|---|---|
| ECDSA | NIST P-256 | `CKM_ECDSA` |
| ECDSA | NIST P-384 | `CKM_ECDSA` |
| EdDSA | Ed25519 | `CKM_EDDSA` |
| RSA PKCS#1 v1.5 | 2048 bit | `CKM_RSA_PKCS` |
| RSA PKCS#1 v1.5 | 4096 bit | `CKM_RSA_PKCS` |

---

## Prerequisites

- A running Cosmian KMS instance (see the [Quick-start guide](../quick_start.md)).
- The `ckms` CLI configured and authenticated against it.
- OpenSSH client ≥ 7.3 (ships with every modern Linux / macOS).
- The `libcosmian_pkcs11.so` (Linux) or `libcosmian_pkcs11.dylib` (macOS) shared library. If you
  installed the Cosmian KMS CLI package this is already at `/usr/local/lib/libcosmian_pkcs11.so`.

---

## Step 1 — Create the SSH key pair in the KMS

Tag the key pair with `ssh-auth` so that the PKCS#11 provider can discover it.

### ECDSA P-256 (recommended)

```bash
ckms ec keys create --curve nist-p256 --tag ssh-auth --tag my-laptop
```

### Ed25519 (non-FIPS builds only)

```bash
ckms ec keys create --curve ed25519 --tag ssh-auth --tag my-laptop
```

### RSA 4096

```bash
ckms rsa keys create --size_in_bits 4096 --tag ssh-auth --tag my-laptop
```

After the command succeeds, record the private-key ID and public-key ID printed by the CLI:

```text
Private key unique identifier  : 3fa85f64-5717-4562-b3fc-2c963f66afa6
Public  key unique identifier  : 3fa85f64-5717-4562-b3fc-2c963f66afa6_pk
```

---

## Step 2 — Export the public key for `authorized_keys`

Export the public key from the KMS in PKCS#8 / SubjectPublicKeyInfo format and then convert it to
the OpenSSH wire format that goes into `authorized_keys`.

```bash
# Export the public key as PEM-encoded SubjectPublicKeyInfo (SPKI)
ckms ec keys export \
  --key-id 3fa85f64-5717-4562-b3fc-2c963f66afa6_pk \
  --key-format pkcs8-pem \
  /tmp/id_ecdsa_kms.pub.pem

# Convert to OpenSSH public key format
ssh-keygen -f /tmp/id_ecdsa_kms.pub.pem -e -m pkcs8 > /tmp/id_ecdsa_kms.pub

# Optionally add a comment
cat /tmp/id_ecdsa_kms.pub
# ecdsa-sha2-nistp256 AAAA…== (no comment yet)

# Append to authorized_keys on each target server
cat /tmp/id_ecdsa_kms.pub | ssh user@server "cat >> ~/.ssh/authorized_keys"
```

For RSA keys, substitute `ckms ec keys export` with `ckms rsa keys export`.

---

## Step 3 — Configure the OpenSSH client

### Option A — Per-connection flag

```bash
ssh -I /usr/local/lib/libcosmian_pkcs11.so user@server
```

### Option B — Add to `~/.ssh/config` (permanent)

```ssh-config
Host *
    PKCS11Provider /usr/local/lib/libcosmian_pkcs11.so
```

Or scope it to a specific host:

```ssh-config
Host my-server.example.com
    User     alice
    PKCS11Provider /usr/local/lib/libcosmian_pkcs11.so
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `COSMIAN_KMS_CLI_CONF` | `~/.cosmian/kms.toml` | Path to the `ckms` client config (KMS URL, credentials). |
| `COSMIAN_PKCS11_LOGGING_LEVEL` | `info` | Log level for the provider: `trace`, `debug`, `info`, `warn`, `error`. |
| `COSMIAN_PKCS11_SSH_KEY_TAG` | `ssh-auth` | The KMS vendor tag used to discover SSH key pairs. Override to use a custom tag. |

---

## Verification

```bash
# List the key pairs that the provider will expose
COSMIAN_PKCS11_LOGGING_LEVEL=debug ssh -I /usr/local/lib/libcosmian_pkcs11.so user@server whoami
```

You should see lines similar to the following in the debug output and the remote command's output:

```text
debug1: provider /usr/local/lib/libcosmian_pkcs11.so: manufacturerID <cosmian>
debug1: have 1 keys from provider /usr/local/lib/libcosmian_pkcs11.so
```

---

## Troubleshooting

### `no keys found` or authentication rejected

- Verify the public key is in `~/.ssh/authorized_keys` on the server.
- Check the KMS tag: the private and public key pair must be tagged with `ssh-auth` (or the
  value you set in `COSMIAN_PKCS11_SSH_KEY_TAG`).
- Run `ckms ec keys locate --tag ssh-auth` to confirm the KMS returns your key.

### `provider ... not supported` or `unsupported algorithm`

- The Ed25519 / EdDSA mechanism (`CKM_EDDSA`) requires a non-FIPS build of the Cosmian KMS and
  library. In FIPS mode, use ECDSA P-256 or RSA instead.

### `COSMIAN_KMS_CLI_CONF not set` or connection refused

- The library reads the same `ckms` configuration file as the CLI. Make sure the environment
  variable points to a valid configuration and that the KMS server is reachable.

### macOS — library not loaded

macOS requires code-signed PKCS#11 libraries to be loaded by SSH. Use the `.dylib` built for
macOS and ensure it is in your library path:

```bash
ssh -I /usr/local/lib/libcosmian_pkcs11.dylib user@server
```
