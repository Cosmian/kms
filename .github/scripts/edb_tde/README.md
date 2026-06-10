# EDB PostgreSQL TDE — KMIP Compliance Test Suite

Tests that Cosmian KMS is fully compatible with **EDB Postgres Advanced Server 17
Transparent Data Encryption (TDE)**, exercising the real `edb_tde_kmip_client.py`
shipped inside the EDB image.

> **`EDB_SUBSCRIPTION_TOKEN` is required.** The test suite fails immediately if the
> variable is not set.

---

## Directory contents

| File | Purpose |
|---|---|
| `test_edb_tde.sh` | Main test runner (see [Tests](#tests) below) |
| `edb_tde_kmip_client_sim.py` | Simulation used only for master key creation (real client lacks this command) |
| `edb_startup.sh` | Container entrypoint: runs `initdb -y --key-wrap-command …` then starts `postgres` |
| `Dockerfile.edb` | Extends the EDB base image: installs PyKMIP for Python 3.12 + `ssl.wrap_socket` shim |
| `sitecustomize.py` | Restores `ssl.wrap_socket` (removed in Python 3.12) so PyKMIP 0.10.0 works |
| `pykmip.conf` | PyKMIP client config for the **host** (used by the simulation client for master key creation) |
| `pykmip_docker.conf` | PyKMIP client config mounted **inside the EDB container** (`host.docker.internal:15696`) |

---

## Running the tests

The test suite is invoked by `nix.sh` (non-FIPS only):

```bash
# Requires EDB_SUBSCRIPTION_TOKEN
EDB_SUBSCRIPTION_TOKEN=<token> bash .github/scripts/nix.sh --variant non-fips test edb_tde
```

You can also run individual sub-suites directly:

```bash
EDB_SUBSCRIPTION_TOKEN=<token> bash .github/scripts/edb_tde/test_edb_tde.sh [all|create|pykmip|thales|rotation|postgres]
```

---

## Tests

### Modes

All wrap/unwrap operations use the real `edb_tde_kmip_client.py` inside the running EDB
container via `docker exec`. Master key creation uses `edb_tde_kmip_client_sim.py`
because the real client does not implement a `create_master_key` command.

---

### Test 1 — EDB Postgres TDE: login & start container *(real mode only)*

**Sub-command:** `all` (when token is set)

1. Logs in to `docker.enterprisedb.com` with `EDB_SUBSCRIPTION_TOKEN`.
2. Creates an AES-256 master key in the Cosmian KMS via the simulation client.
3. Starts the `edb-tde` Docker Compose service.
   `initdb -y --key-wrap-command` calls the **real** `edb_tde_kmip_client.py` inside
   the container to seal the freshly-generated cluster DEK against the KMS over KMIP/TLS.
4. Polls `/usr/edb/as17/bin/pg_isready` (up to 3 minutes) until Postgres accepts
   connections on port 5444.

**What it proves:** the KMS correctly handles the `Encrypt` KMIP operation called by
`edb_tde_kmip_client.py` during `initdb`, sealing the cluster DEK.

---

### Test 2 — Create master key (AES-256)

**Sub-command:** `create`, `all`

Creates an AES-256 symmetric key via `ProxyKmipClient.create()` (PyKMIP) and confirms a
non-empty UID is returned. The key is stored in `$TEST_WORKDIR/master_key_uid.txt` and
reused by all subsequent tests.

In real mode this step is a no-op — the key was already created during test 1.

---

### Test 3 — PyKMIP variant: wrap/unwrap DEK

**Sub-command:** `pykmip`, `all`

Exercises the **`--variant=pykmip`** wire format:

1. Generates a random 32-byte DEK.
2. **Wrap** (`encrypt`): calls `edb_tde_kmip_client.py encrypt --variant=pykmip`.
   The client uses KMIP `Encrypt` with AES-256-CBC + PKCS5 padding, random IV.
   Output wire format: `[16-byte IV][ciphertext]` written to a file.
3. **Unwrap** (`decrypt`): calls `edb_tde_kmip_client.py decrypt --variant=pykmip`.
   The client calls KMIP `Decrypt` with the IV passed as `IVCounterNonce` and the
   ciphertext as `Data`.
4. Asserts the unwrapped bytes equal the original DEK (byte-exact `cmp`).

---

### Test 4 — Thales variant: wrap/unwrap DEK

**Sub-command:** `thales`, `all`

Exercises the **`--variant=thales`** wire format (used by Thales Luna HSM clients):

1. Generates a random 32-byte DEK.
2. **Wrap** (`encrypt`): same AES-256-CBC encrypt path as the pykmip variant.
   Output wire format: `[16-byte IV][ciphertext]` (identical bytes on the wire).
3. **Unwrap** (`decrypt`): calls KMIP `Decrypt` with `Data = IV + ciphertext` and **no
   separate `IVCounterNonce` field**.
   The KMS treats a missing `IVCounterNonce` as an all-zero IV, then strips the first
   16 bytes from the decrypted output (the prepended IV). See
   `crate/server/src/core/operations/decrypt.rs`.
4. Asserts the unwrapped bytes equal the original DEK.

---

### Test 5 — Key rotation (re-wrap with new key)

**Sub-command:** `rotation`, `all`

Simulates an operator rotating the master encryption key:

1. Wraps a DEK with the **old** master key (pykmip variant).
2. Creates a **new** AES-256 master key.
3. Re-wraps: pipes `unwrap(old_key)` directly into `wrap(new_key)` — no plaintext DEK
   ever touches disk.
4. Unwraps with the new key and asserts the result equals the original DEK.

---

### Test 6 — Multiple DEK sizes

**Sub-command:** `all`

Verifies that DEKs of non-standard sizes all round-trip correctly through the pykmip
variant. Tested sizes: **16, 32, 48, 64, 128 bytes**.

This guards against AES-CBC padding bugs that would silently truncate or corrupt
plaintexts that are not a multiple of 16 bytes after decryption.

---

### Test 7 — EDB Postgres TDE: verify encryption active *(real mode only)*

**Sub-command:** `postgres`, `all` (when `EDB_CONTAINER_ACTIVE=1`)

Connects to the running EDB Postgres instance and verifies end-to-end that the cluster
was initialised with TDE:

1. **`SELECT data_encryption_version FROM pg_control_init()`** — asserts the value is
   `1` (TDE active). A value of `0` means the cluster was not initialised with
   `--data-encryption`.
2. **Encrypted row roundtrip**: creates `tde_test(id int, secret text)`, inserts one
   row, and reads it back — confirming that the storage layer encrypts and decrypts
   transparently via the cluster DEK that was sealed by the KMS.

---

## Architecture

```text
┌─────────────────────┐   KMIP/TLS    ┌──────────────────────────┐
│  EDB container      │  port 15696   │  Cosmian KMS             │
│                     │◄─────────────►│  (SQLite, non-FIPS)      │
│  edb_tde_kmip_      │               │                          │
│  client.py          │               │  AES-256-CBC Encrypt /   │
│  (real, Python 3.12)│               │  Decrypt operations      │
│                     │               └──────────────────────────┘
│  initdb -y          │
│  --key-wrap-command │   host.docker.internal:15696
│                     │
│  postgres -D        │
│  /tmp/pgdata_tde    │
└─────────────────────┘
         ▲
         │  docker exec
         │
┌─────────────────────┐
│  test_edb_tde.sh    │
│  (host)             │
└─────────────────────┘
```

The KMS KMIP socket server listens on `0.0.0.0:15696` with mTLS (client certificate
authentication). Inside the container, `host.docker.internal` resolves to the Docker
host IP via the `extra_hosts` entry in `docker-compose.yml`.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `EDB_SUBSCRIPTION_TOKEN` | No | EDB registry token. When set, starts the real EDB container and uses the real client. |
| `EDB_PGPASSWORD` | No | Postgres password for the `enterprisedb` superuser (default: `kms_test`). |
| `PYTHON_CMD` | No | Python interpreter to use on the host (default: `python`). |

---

## Prerequisites

| Component | Notes |
|---|---|
| Cosmian KMS | Must be running on port 9998 (HTTP) and 15696 (KMIP/TLS) before the tests start. `nix.sh` starts it automatically. |
| Docker | Required — `EDB_SUBSCRIPTION_TOKEN` must be set. |
| PyKMIP | Must be importable by `$PYTHON_CMD` on the host (for master key creation via sim client). |
| mTLS certificates | Auto-generated from `test_data/certificates/client_server/` by `nix.sh`. |
